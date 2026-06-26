/*
 * Smart EQ Offset Finder - GPL Edition
 * Copyright 2007-2009, Carpathian <Carpathian01@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "stdafx.h"
#include "EQGameScanner.h"

typedef uint64_t* PQWORD;

/*
 * Offset Value Storage
 */
namespace EQPrimaryOffsets
{
	QWORD Zone = 0x0;
	QWORD ZoneInfo = 0x0;
	QWORD SpawnHeader = 0x0;
	QWORD CharInfo = 0x0;
	QWORD Items = 0x0;
	QWORD Target = 0x0;
	QWORD World = 0x0;
};

namespace EQSpawnInfoOffsets
{
	QWORD Next = 0x0;
	QWORD Prev = 0x0;
	QWORD Lastname = 0x0;
	QWORD X = 0x0;
	QWORD Y = 0x0;
	QWORD Z = 0x0;
	QWORD Speed = 0x0;
	QWORD Heading = 0x0;
	QWORD Name = 0x0;
	QWORD Type = 0x0;
	QWORD SpawnId = 0x0;
	QWORD Hide = 0x0;
	QWORD Level = 0x0;
	QWORD Race = 0x0;
	QWORD Class = 0x0;
};

EQGameScanner::EQGameScanner(void) {}

EQGameScanner::~EQGameScanner(void) {}

// ---------------------------------------------------------------------------
// PE helpers — parse section table once per exe path change
// ---------------------------------------------------------------------------

bool EQGameScanner::parsePESections()
{
	m_sections.clear();
	m_imageBase = 0;

	std::ifstream f(executablePath.c_str(), std::ios::binary);
	if (!f)
		return false;

	// MZ header
	WORD mz = 0;
	f.read(reinterpret_cast<char*>(&mz), 2);
	if (mz != 0x5A4D)
		return false;

	// e_lfanew
	f.seekg(0x3C);
	DWORD peOff = 0;
	f.read(reinterpret_cast<char*>(&peOff), 4);

	// PE signature
	f.seekg(peOff);
	DWORD sig = 0;
	f.read(reinterpret_cast<char*>(&sig), 4);
	if (sig != 0x00004550)  // "PE\0\0"
		return false;

	// COFF header
	WORD numSections = 0, optHdrSize = 0;
	f.seekg(peOff + 6);
	f.read(reinterpret_cast<char*>(&numSections), 2);
	f.seekg(peOff + 20);
	f.read(reinterpret_cast<char*>(&optHdrSize), 2);

	// Optional header: ImageBase at offset 24 from start of optional header (PE64)
	f.seekg(peOff + 24 + 24);
	f.read(reinterpret_cast<char*>(&m_imageBase), 8);

	// Section table
	DWORD secTableOff = peOff + 24 + optHdrSize;
	for (WORD i = 0; i < numSections; ++i)
	{
		f.seekg(secTableOff + i * 40);
		char nameBuf[9] = {};
		f.read(nameBuf, 8);
		DWORD virtSize = 0, virtOff = 0, rawSize = 0, rawOff = 0;
		f.read(reinterpret_cast<char*>(&virtSize), 4);
		f.read(reinterpret_cast<char*>(&virtOff),  4);
		f.read(reinterpret_cast<char*>(&rawSize),  4);
		f.read(reinterpret_cast<char*>(&rawOff),   4);
		m_sections.push_back({ rawOff, rawSize, virtOff });
	}
	return true;
}

DWORD EQGameScanner::fileOffsetToRVA(DWORD fileOffset) const
{
	for (const auto& s : m_sections)
	{
		if (fileOffset >= s.rawOff && fileOffset < s.rawOff + s.rawSize)
			return s.virtOff + (fileOffset - s.rawOff);
	}
	return 0;
}

void EQGameScanner::setExe(TCHAR* str)
{
	executablePath = str;
}

bool EQGameScanner::executableExists() const
{
	std::ifstream file(executablePath.c_str(), std::ios::in);

	if (file)
	{
		file.close();
		return true;
	}

	return false;
}

QWORD EQGameScanner::findEQPointerOffset(DWORD startAddress, std::size_t blockSize, const PBYTE byteMask, const PCHAR charMask)
{
	std::ifstream file(executablePath.c_str(), std::ios::in | std::ios::binary);

	// If the file can't be opened, return NULL for pointer offset.
	if (!file)
		return 0;

	std::string maskStr(charMask);

	if (maskStr.empty())
		return 0;

	// Detect RIP-relative mode: mask contains 'r' characters (4-byte displacement).
	// In this mode we wildcard the displacement bytes and compute the resolved VA as:
	//   IMAGE_BASE + fileOffsetToRVA(match_file_off + r_pos + 4) + (int32_t)disp32
	bool ripMode = (maskStr.find('r') != std::string::npos);

	int typelen = 0;
	typelen = (int)maskStr.find_last_of("t") - (int)maskStr.find_first_of("t") + 1;

	if (typelen < 1)
		typelen = 4;

	// Setup our temporary storage variables
	std::vector<BYTE> buffer(blockSize, 0); // Using vector for automatic memory management
	QWORD matchAddr = 0;
	bool found = false;

	// Move get pointer to the start of the block we want to search
	file.seekg(startAddress, std::ios::beg);
	file.read(reinterpret_cast<char*>(buffer.data()), blockSize);

	// Search for a position that fits our masks in memory.
	for (DWORD i = 0; i < blockSize; ++i)
	{
		if (compareData(buffer.data() + i, byteMask, charMask))
		{
			matchAddr = i;

			if (ripMode)
			{
				// Validate by computing the resolved VA and checking it looks like an x64 address.
				size_t rPos = maskStr.find_first_of("r");
				int32_t disp32 = *reinterpret_cast<int32_t*>(buffer.data() + matchAddr + rPos);
				DWORD nextInstrFileOff = startAddress + (DWORD)matchAddr + (DWORD)rPos + 4;
				if (m_sections.empty())
					parsePESections();
				DWORD nextInstrRVA = fileOffsetToRVA(nextInstrFileOff);
				if (nextInstrRVA == 0) { matchAddr = 0; continue; }
				QWORD resolvedVA = m_imageBase + nextInstrRVA + (int64_t)disp32;
				if (resolvedVA >= 0x100000000ULL)
				{
					found = true;
					break;
				}
			}
			else
			{
				QWORD checkRet = 0;
				if (typelen == 1)
					checkRet = *reinterpret_cast<PBYTE>(buffer.data() + matchAddr + maskStr.find_first_of("t"));
				else if (typelen == 2)
					checkRet = *reinterpret_cast<PWORD>(buffer.data() + matchAddr + maskStr.find_first_of("t"));
				else if (typelen == 8)
					checkRet = *reinterpret_cast<PQWORD>(buffer.data() + matchAddr + maskStr.find_first_of("t"));
				else
					checkRet = *reinterpret_cast<PDWORD>(buffer.data() + matchAddr + maskStr.find_first_of("t"));

				// x64 EQ addresses are >= 4GB; x86 EQ addresses were < 512MB
				if ((typelen >= 8 && checkRet >= 0x100000000ULL) || (typelen < 8 && checkRet < 536870912))
				{
					found = true;
					break;
				}
			}

			matchAddr = 0;
		}
	}

	// Close the file before returning
	file.close();

	// If we didn't find a match, return 0
	if (!found)
		return 0;

	// RIP-relative: compute IMAGE_BASE + rva(next_instr) + disp32
	if (ripMode)
	{
		size_t rPos = maskStr.find_first_of("r");
		int32_t disp32 = *reinterpret_cast<int32_t*>(buffer.data() + matchAddr + rPos);
		DWORD nextInstrFileOff = startAddress + (DWORD)matchAddr + (DWORD)rPos + 4;
		DWORD nextInstrRVA = fileOffsetToRVA(nextInstrFileOff);
		if (nextInstrRVA == 0) return 0;
		return m_imageBase + nextInstrRVA + (int64_t)disp32;
	}

	// Legacy: read the direct value at the 't' position
	QWORD nRet;
	if (typelen == 1)
		nRet = *reinterpret_cast<PBYTE>(buffer.data() + matchAddr + maskStr.find_first_of("t"));
	else if (typelen == 2)
		nRet = *reinterpret_cast<PWORD>(buffer.data() + matchAddr + maskStr.find_first_of("t"));
	else if (typelen == 8)
		nRet = *reinterpret_cast<PQWORD>(buffer.data() + matchAddr + maskStr.find_first_of("t"));
	else
		nRet = *reinterpret_cast<PDWORD>(buffer.data() + matchAddr + maskStr.find_first_of("t"));

	return nRet;
}


QWORD EQGameScanner::findEQStructureOffset(DWORD startAddress, std::size_t blockSize, const PBYTE byteMask, const PCHAR charMask, const QWORD baseEQPointerAddress)
{
	QWORD nRet = 0;

	std::string maskStr = charMask;

	if (maskStr.empty()) {
		return nRet;
	}

	// Create a new, editable copy of byteMask using std::vector for automatic memory management
	std::vector<BYTE> newByteMask(maskStr.size());
	memcpy(newByteMask.data(), byteMask, maskStr.size());

	// Find the position of 'o' in the character mask
	size_t pointerPos = maskStr.find_first_of('o');
	if (pointerPos == std::string::npos || pointerPos + sizeof(QWORD) > newByteMask.size()) {
		// Invalid mask or pointer out of bounds, return 0
		return nRet;
	}

	// Replace the EQPointer in our byteMask with the EQPointer given as an argument
	*reinterpret_cast<QWORD*>(newByteMask.data() + pointerPos) = baseEQPointerAddress;

	// Use the updated byteMask to locate the EQStructureOffset
	nRet = findEQPointerOffset(startAddress, blockSize, newByteMask.data(), charMask);

	return nRet;
}


// Thanks to dom1n1k for the piece of code this is based off of.
bool EQGameScanner::compareData(PBYTE data, PBYTE byteMask, PCHAR charMask)
{
	for (; *charMask; ++charMask, ++data, ++byteMask)
	{
		if ((*charMask == 'x' || *charMask == 'o') && *data != *byteMask)
			return false;
	}
	return (*charMask) == NULL;
}

bool EQGameScanner::ScanExecutable(HWND hDlg, IniReaderInterface* ir_intf, NetworkServerInterface* net_intf, bool write_out)
{
	if (!executableExists())
	{
		SetDlgItemText(hDlg, IDC_EDIT2, "Error: Could not locate the specified executable file.");
		return false;
	}

	bool reload = false;
	std::ostringstream outputStream;
	std::ostringstream findResults;

	// Update the File Info section
	updateFileInfoSection(outputStream, ir_intf, write_out);

	// Process each memory offset
	std::vector<std::pair<std::string, int>> offsets = {
		{"ZoneAddr", NetworkServer::OT_zonename},
		{"SpawnHeaderAddr", NetworkServer::OT_spawnlist},
		{"CharInfo", NetworkServer::OT_self},
		{"ItemsAddr", NetworkServer::OT_ground},
		{"TargetAddr", NetworkServer::OT_target},
		{"WorldAddr", NetworkServer::OT_world}
	};

	// Debug: dump INI read + PE parse results — prepended to final output
	{
		bool peOk = parsePESections();
		findResults << "[Debug]\r\n";
		findResults << "exe: " << executablePath << "\r\n";
		findResults << "parsePE: " << (peOk ? "OK" : "FAIL") << "  imageBase=0x" << std::hex << m_imageBase << "  sections=" << std::dec << m_sections.size() << "\r\n";
		DWORD zStart  = (DWORD)ir_intf->readIntegerEntry("ZoneAddr", "Start");
		std::string zPat  = ir_intf->readEscapeStrings("ZoneAddr", "Pattern");
		std::string zMask = ir_intf->readStringEntry("ZoneAddr", "Mask");
		findResults << "ZoneAddr  start=0x" << std::hex << zStart << "  patLen=" << std::dec << zPat.length() << "  maskLen=" << zMask.length() << "\r\n";
		findResults << "ZoneAddr  mask=[" << zMask << "]\r\n\r\n";
	}

	for (const auto& offset : offsets)
	{
		QWORD matchAddr = findAndProcessOffset(hDlg, offset.first, "Start", ir_intf, net_intf, outputStream, write_out);
		handleMatchResult(hDlg, matchAddr, net_intf, offset.second, offset.first, ir_intf, outputStream, write_out, reload);
	}

	// Update the dialog with the results
	std::string resultText = findResults.str() + outputStream.str();
	SetDlgItemText(hDlg, IDC_EDIT2, resultText.c_str());

	return reload;
}

void EQGameScanner::updateFileInfoSection(std::ostringstream& outputStream, IniReaderInterface* ir_intf, bool write_out) {
	// Initialize file attributes and retrieve the last write time
	WIN32_FILE_ATTRIBUTE_DATA fileData;
	if (!GetFileAttributesEx(executablePath.c_str(), GetFileExInfoStandard, &fileData)) {
		return; // Early return if file attributes can't be retrieved
	}
	SYSTEMTIME st;
	FileTimeToSystemTime(&fileData.ftLastWriteTime, &st);
	TCHAR szFileDate[16]; // A smaller buffer size is sufficient
	GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, nullptr, szFileDate, sizeof(szFileDate) / sizeof(szFileDate[0]));

	// Write the date to the INI file if necessary
	if (write_out) {
		ir_intf->writeStringEntry("File Info", "PatchDate", szFileDate);
	}
	outputStream << "[File Info]\r\n"
		<< "PatchDate=" << szFileDate << "\r\n\r\n"
		<< "[Port]\r\n"
		<< "Port=" << ir_intf->readIntegerEntry("Port", "Port") << "\r\n\r\n"
		<< "[Memory Offsets]\r\n";
}


QWORD EQGameScanner::findAndProcessOffset(HWND hDlg, const std::string& section, const std::string& entry, IniReaderInterface* ir_intf, NetworkServerInterface* net_intf, std::ostringstream& outputStream, bool write_out)
{
	DWORD mystart = (DWORD)ir_intf->readIntegerEntry(section.c_str(), entry.c_str());
	std::string mypattern = ir_intf->readEscapeStrings(section.c_str(), "Pattern");
	std::string mymask = ir_intf->readStringEntry(section.c_str(), "Mask");

	QWORD matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());
	outputStream << section << "=0x" << std::hex << matchAddr;
	return matchAddr;
}

void EQGameScanner::handleMatchResult(HWND hDlg, QWORD matchAddr, NetworkServerInterface* net_intf, int offsetType, const std::string& offsetName, IniReaderInterface* ir_intf, std::ostringstream& outputStream, bool write_out, bool& reload)
{
	if (matchAddr != 0) {
		if (matchAddr == net_intf->current_offset(offsetType)) {
			outputStream << " # Match\r\n";
		}
		else {
			if (write_out) {
				std::stringstream strm;
				strm << "0x" << std::hex << matchAddr;
				if (ir_intf->writeStringEntry("Memory Offsets", offsetName.c_str(), strm.str().c_str())) {
					reload = true;
					outputStream << " # Written to ini file\r\n";
				}
				else {
					outputStream << " # Found - Write failed\r\n";
				}
			}
			else {
				outputStream << " # Does not match ini file.\r\n";
				EnableWindow(GetDlgItem(hDlg, IDC_BUTTON2), TRUE);
			}
		}
	}
	else {
		outputStream << " # Not Found\r\n";
	}
}

void EQGameScanner::ScanSecondary(HWND hDlg, IniReaderInterface* ir_intf, NetworkServerInterface* net_intf)
{
	if (!executableExists())
	{
		SetDlgItemText(hDlg, IDC_EDIT2, "Error: Could not locate the specified executable file.");
		return;
	}

	// We'll use this for comparisons
	QWORD matchAddr = 0;

	std::ostringstream findResults;
	std::ostringstream outputStream;

	WIN32_FILE_ATTRIBUTE_DATA FileData = { 0 };

	if (GetFileAttributesEx(executablePath.c_str(), GetFileExInfoStandard, &FileData))
	{
		TCHAR szFileDate[255];
		FILETIME ftLastMod = FileData.ftLastWriteTime;
		SYSTEMTIME st;
		FileTimeToSystemTime(&ftLastMod, &st);
		GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, szFileDate, 255);
		string::size_type index = executablePath.find_last_of("\\/");
		string myfilename = executablePath.substr(index + 1, executablePath.size()).c_str();
		findResults << myfilename.c_str() << " Modified=" << szFileDate << "\r\n";
	}

	EQPrimaryOffsets::CharInfo = net_intf->current_offset((int)NetworkServer::OT_self);

	DWORD mystart;
	string mypattern;
	string mymask;

	mystart = (DWORD)ir_intf->readIntegerEntry("CharInfo", "Start");
	mypattern = ir_intf->readEscapeStrings("CharInfo", "Pattern");
	mymask = ir_intf->readStringEntry("CharInfo", "Mask");

	// CharInfo
	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	if (matchAddr != 0)
	{
		// If we match char info offset by pattern search use it
		EQPrimaryOffsets::CharInfo = matchAddr;
	}
	else
	{
		// Otherwise use what is in the myseqserver.ini file
		EQPrimaryOffsets::CharInfo = net_intf->current_offset((int)NetworkServer::OT_self);
	}

	outputStream << "SpawnInfo Offsets" << "\r\n";
	matchAddr = 0;

	// SpawnInfo::NextOffset
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoNextOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoNextOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoNextOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "NextOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::PrevOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoPrevOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoPrevOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoPrevOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "PrevOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::LastnameOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoLastnameOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoLastnameOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoLastnameOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "LastnameOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::XOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoXOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoXOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoXOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "XOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::YOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoYOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoYOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoYOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "YOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::ZOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoZOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoZOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoZOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "ZOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::SpeedOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoSpeedOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoSpeedOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoSpeedOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "SpeedOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::HeadingOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoHeadingOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoHeadingOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoHeadingOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "HeadingOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::NameOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoNameOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoNameOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoNameOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "NameOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::TypeOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoTypeOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoTypeOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoTypeOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "TypeOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::SpawnIDOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoSpawnIDOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoSpawnIDOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoSpawnIDOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "SpawnIDOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::OwnerIDOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoOwnerIDOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoOwnerIDOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoOwnerIDOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "OwnerIDOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::HideOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoHideOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoHideOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoHideOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "HideOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::Prev
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoLevelOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoLevelOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoLevelOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "LevelOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::Prev
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoRaceOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoRaceOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoRaceOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "RaceOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::ClassOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoClassOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoClassOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoClassOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "ClassOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::PrimaryOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoPrimaryOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoPrimaryOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoPrimaryOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "PrimaryOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// SpawnInfo::OffhandOffset
	matchAddr = 0;
	mystart = (DWORD)ir_intf->readIntegerEntry("SpawnInfoOffhandOffset", "Start");
	mypattern = ir_intf->readEscapeStrings("SpawnInfoOffhandOffset", "Pattern");
	mymask = ir_intf->readStringEntry("SpawnInfoOffhandOffset", "Mask");

	matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

	outputStream << "OffhandOffset" << ":" << "\r\n";
	outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
	outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
	outputStream << "\r\n";

	// WorldInfo offsets
	outputStream << "WorldInfo Offsets\r\n";

	struct { const char* label; const char* section; } worldOffsets[] = {
		{ "WorldHourOffset",   "WorldInfoHourOffset"   },
		{ "WorldMinuteOffset", "WorldInfoMinuteOffset" },
		{ "WorldDayOffset",    "WorldInfoDayOffset"    },
		{ "WorldMonthOffset",  "WorldInfoMonthOffset"  },
		{ "WorldYearOffset",   "WorldInfoYearOffset"   },
	};

	for (const auto& wo : worldOffsets)
	{
		matchAddr = 0;
		mystart   = (DWORD)ir_intf->readIntegerEntry(wo.section, "Start");
		mypattern = ir_intf->readEscapeStrings(wo.section, "Pattern");
		mymask    = ir_intf->readStringEntry(wo.section, "Mask");

		matchAddr = findEQPointerOffset(mystart, 0x100000, (PBYTE)mypattern.c_str(), (PCHAR)mymask.c_str());

		outputStream << wo.label << ":\r\n";
		outputStream << "| Match Found @ " << ((matchAddr == 0) ? "FALSE" : "TRUE") << "\r\n";
		outputStream << "| Offset -> 0x" << std::hex << matchAddr << "\r\n";
		outputStream << "\r\n";
	}

	findResults << "\r\n";

	std::string v = findResults.str() + outputStream.str();
	SetDlgItemText(hDlg, IDC_EDIT2, v.c_str());

	return;
}

// ---------------------------------------------------------------------------
// FindAndWriteAllPatterns — pattern discovery helpers
// ---------------------------------------------------------------------------

static int fpCountMatches(const BYTE* textBuf, size_t textSize,
                           const BYTE* pat, const char* mask, size_t patLen)
{
    if (textSize < patLen) return 0;
    int count = 0;
    for (size_t i = 0; i <= textSize - patLen; ++i)
    {
        bool ok = true;
        for (size_t j = 0; j < patLen && ok; ++j)
            if (mask[j] == 'x' && textBuf[i+j] != pat[j]) ok = false;
        if (ok && ++count > 1) return count;
    }
    return count;
}

// Returns file offsets of the start of each 7-byte RIP-relative instruction
// that resolves to targetVA.
static std::vector<DWORD> fpFindRipRefs(
    const BYTE* textBuf, size_t textSize, DWORD textRawOff, DWORD textVirtOff,
    QWORD targetVA, QWORD imageBase)
{
    static const BYTE kRex[] = {0x44,0x45,0x48,0x49,0x4C,0x4D};
    static const BYTE kOp[]  = {0x83,0x85,0x87,0x89,0x8B,0x8D,0x3B};
    std::vector<DWORD> hits;
    for (size_t i = 0; i + 7 <= textSize; ++i)
    {
        bool rex = false, op = false;
        for (BYTE r : kRex) if (textBuf[i]   == r) { rex = true; break; }
        if (!rex) continue;
        for (BYTE o : kOp)  if (textBuf[i+1] == o) { op  = true; break; }
        if (!op) continue;
        if ((textBuf[i+2] & 0xC7) != 0x05) continue;
        int32_t disp; memcpy(&disp, textBuf + i + 3, 4);
        if ((QWORD)(imageBase + textVirtOff + i + 7) + (int64_t)disp == targetVA)
            hits.push_back(textRawOff + (DWORD)i);
    }
    return hits;
}

// Returns file offsets of the displacement bytes in struct-access instructions.
static std::vector<DWORD> fpFindStructAccesses(
    const BYTE* textBuf, size_t textSize, DWORD textRawOff, DWORD offsetValue)
{
    std::vector<DWORD> hits;
    if (offsetValue > 127)
    {
        BYTE tgt[4]; int32_t v = (int32_t)offsetValue; memcpy(tgt, &v, 4);
        for (size_t i = 2; i + 4 <= textSize; ++i)
        {
            if (memcmp(textBuf + i, tgt, 4) != 0) continue;
            BYTE prev = textBuf[i-1];
            if ((prev & 0xC0) == 0x80 && (prev & 0x07) != 0x04 && (prev & 0x07) != 0x05)
                hits.push_back(textRawOff + (DWORD)i);
            else if ((prev & 0x07) == 0x04 && i >= 2 && (textBuf[i-2] & 0xC0) == 0x80)
                hits.push_back(textRawOff + (DWORD)i);
        }
    }
    else
    {
        for (size_t i = 1; i + 1 <= textSize; ++i)
        {
            if (textBuf[i] != (BYTE)offsetValue) continue;
            BYTE prev = textBuf[i-1];
            if ((prev & 0xC0) == 0x40 && (prev & 0x07) != 0x04)
                hits.push_back(textRawOff + (DWORD)i);
        }
    }
    return hits;
}

// Pick the hit with the fewest matches (ideally 1), build pattern, write to INI.
// dispFileHits: file offsets of displacement start.
// ctxBefore: exact-match bytes before displacement (includes instr prefix for primary).
// dispMask: 'r' for RIP-relative primary, 't' for struct-offset secondary.
static bool fpWritePattern(
    const BYTE* exeData, size_t exeSize,
    const BYTE* textBuf, size_t textSize, DWORD textRawOff,
    const std::vector<DWORD>& dispFileHits,
    int ctxBefore, int dispSize, int ctxAfter, char dispMask,
    const std::string& section,
    IniReaderInterface* ir_intf,
    std::ostringstream& out)
{
    int patLen = ctxBefore + dispSize + ctxAfter;
    std::string mask(ctxBefore, 'x');
    mask += std::string(dispSize, dispMask);
    mask += std::string(ctxAfter, 'x');

    int bestCount = INT_MAX;
    DWORD bestStart = 0;
    std::vector<BYTE> bestPat;

    for (DWORD dfo : dispFileHits)
    {
        if (dfo < (DWORD)ctxBefore) continue;
        DWORD patStart = dfo - ctxBefore;
        DWORD patEnd   = dfo + dispSize + ctxAfter;
        if (patStart < textRawOff) continue;
        if (patEnd > (DWORD)(textRawOff + textSize) || patEnd > (DWORD)exeSize) continue;

        const BYTE* pat = exeData + patStart;
        int cnt = fpCountMatches(textBuf, textSize, pat, mask.c_str(), patLen);
        if (cnt > 0 && cnt < bestCount)
        {
            bestCount = cnt;
            bestStart = patStart;
            bestPat   = std::vector<BYTE>(pat, pat + patLen);
        }
        if (bestCount == 1) break;
    }

    if (bestPat.empty())
    {
        out << "  [!] No valid pattern found\r\n";
        return false;
    }

    std::string patStr;
    char hex[6];
    for (int i = 0; i < patLen; ++i)
    {
        sprintf_s(hex, "\\x%02x", (unsigned)bestPat[i]);
        patStr += hex;
    }

    char startStr[32];
    sprintf_s(startStr, "0x%x", bestStart);

    ir_intf->writeStringEntry(section, "Start",   startStr);
    ir_intf->writeStringEntry(section, "Pattern", patStr);
    ir_intf->writeStringEntry(section, "Mask",    mask);

    out << "  count=" << std::dec << bestCount
        << "  start=0x" << std::hex << bestStart;
    out << (bestCount == 1 ? " [unique]\r\n" : " [WARNING: not unique]\r\n");
    return true;
}

// ---------------------------------------------------------------------------
// FindAndWriteAllPatterns — main entry point
// ---------------------------------------------------------------------------

bool EQGameScanner::FindAndWriteAllPatterns(HWND hDlg, IniReaderInterface* ir_intf, NetworkServerInterface* /*net_intf*/)
{
    if (!executableExists())
    {
        SetDlgItemText(hDlg, IDC_EDIT2, "Error: EXE path not set or file not found.");
        return false;
    }

    std::ostringstream out;
    out << "Loading EXE...\r\n";
    SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
    UpdateWindow(hDlg);

    std::ifstream exeFile(executablePath.c_str(), std::ios::binary | std::ios::ate);
    if (!exeFile)
    {
        SetDlgItemText(hDlg, IDC_EDIT2, "Error: Cannot open EXE file.");
        return false;
    }
    size_t fileSize = (size_t)exeFile.tellg();
    exeFile.seekg(0);
    std::vector<BYTE> exeData(fileSize);
    exeFile.read(reinterpret_cast<char*>(exeData.data()), fileSize);
    exeFile.close();

    out << "File: " << (fileSize / 1024 / 1024) << " MB\r\n";
    SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
    UpdateWindow(hDlg);

    // Parse PE header to locate .text section
    if (exeData.size() < 0x40 || memcmp(exeData.data(), "MZ", 2) != 0)
    {
        SetDlgItemText(hDlg, IDC_EDIT2, "Error: Not a valid PE file.");
        return false;
    }
    DWORD peOff = *reinterpret_cast<DWORD*>(exeData.data() + 0x3C);
    if (peOff + 24 > exeData.size() || memcmp(exeData.data() + peOff, "PE\0\0", 4) != 0)
    {
        SetDlgItemText(hDlg, IDC_EDIT2, "Error: PE signature not found.");
        return false;
    }
    WORD  numSec   = *reinterpret_cast<WORD*> (exeData.data() + peOff + 6);
    WORD  optHdrSz = *reinterpret_cast<WORD*> (exeData.data() + peOff + 20);
    QWORD imgBase  = *reinterpret_cast<QWORD*>(exeData.data() + peOff + 24 + 24);
    DWORD secTbl   = peOff + 24 + optHdrSz;

    DWORD textRawOff = 0, textRawSz = 0, textVirtOff = 0;
    for (WORD i = 0; i < numSec; ++i)
    {
        DWORD o = secTbl + i * 40;
        if (o + 40 > (DWORD)exeData.size()) break;
        if (memcmp(exeData.data() + o, ".text\0\0\0", 8) == 0)
        {
            textVirtOff = *reinterpret_cast<DWORD*>(exeData.data() + o + 12);
            textRawSz   = *reinterpret_cast<DWORD*>(exeData.data() + o + 16);
            textRawOff  = *reinterpret_cast<DWORD*>(exeData.data() + o + 20);
            break;
        }
    }
    if (textRawOff == 0)
    {
        SetDlgItemText(hDlg, IDC_EDIT2, "Error: .text section not found in PE.");
        return false;
    }

    const BYTE* textBuf  = exeData.data() + textRawOff;
    size_t      textSize = textRawSz;

    out << "ImageBase: 0x" << std::hex << imgBase << "\r\n";
    out << ".text: 0x" << textRawOff << "  (" << std::dec << textSize / 1024 << " KB)\r\n\r\n";
    SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
    UpdateWindow(hDlg);

    int found = 0, total = 0;

    // ---- Primary patterns (RIP-relative 7-byte instructions) ----
    out << "[Primary Patterns]\r\n";
    SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
    UpdateWindow(hDlg);

    struct { const char* memKey; const char* scanSec; } primaries[] = {
        { "ZoneAddr",        "ZoneAddr"        },
        { "SpawnHeaderAddr", "SpawnHeaderAddr" },
        { "CharInfo",        "CharInfo"        },
        { "TargetAddr",      "TargetAddr"      },
        { "ItemsAddr",       "ItemsAddr"       },
        { "WorldAddr",       "WorldAddr"       },
    };
    for (const auto& p : primaries)
    {
        ++total;
        QWORD targetVA = ir_intf->readIntegerEntry("Memory Offsets", p.memKey);
        out << p.memKey << " (VA=0x" << std::hex << targetVA << "):\r\n";
        SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
        UpdateWindow(hDlg);
        if (targetVA == 0) { out << "  [!] No VA in [Memory Offsets]\r\n"; continue; }

        auto refs = fpFindRipRefs(textBuf, textSize, textRawOff, textVirtOff, targetVA, imgBase);
        out << "  " << std::dec << refs.size() << " RIP-ref(s)\r\n";

        // disp32 starts 3 bytes into each 7-byte instruction; ctxBefore=11 = 8 pre + 3 prefix
        std::vector<DWORD> dispHits;
        for (DWORD instrOff : refs) dispHits.push_back(instrOff + 3);
        if (fpWritePattern(exeData.data(), exeData.size(), textBuf, textSize, textRawOff,
                           dispHits, 11, 4, 6, 'r', p.scanSec, ir_intf, out))
            ++found;

        SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
        UpdateWindow(hDlg);
    }
    out << "\r\n";

    // ---- SpawnInfo secondary patterns ----
    out << "[SpawnInfo Patterns]\r\n";
    SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
    UpdateWindow(hDlg);

    struct { const char* iniKey; const char* scanSec; } spawnInfo[] = {
        { "NextOffset",     "SpawnInfoNextOffset"     },
        { "PrevOffset",     "SpawnInfoPrevOffset"     },
        { "LastnameOffset", "SpawnInfoLastnameOffset" },
        { "XOffset",        "SpawnInfoXOffset"        },
        { "YOffset",        "SpawnInfoYOffset"        },
        { "ZOffset",        "SpawnInfoZOffset"        },
        { "SpeedOffset",    "SpawnInfoSpeedOffset"    },
        { "HeadingOffset",  "SpawnInfoHeadingOffset"  },
        { "NameOffset",     "SpawnInfoNameOffset"     },
        { "TypeOffset",     "SpawnInfoTypeOffset"     },
        { "SpawnIDOffset",  "SpawnInfoSpawnIDOffset"  },
        { "OwnerIDOffset",  "SpawnInfoOwnerIDOffset"  },
        { "HideOffset",     "SpawnInfoHideOffset"     },
        { "LevelOffset",    "SpawnInfoLevelOffset"    },
        { "ClassOffset",    "SpawnInfoClassOffset"    },
        { "RaceOffset",     "SpawnInfoRaceOffset"     },
        { "PrimaryOffset",  "SpawnInfoPrimaryOffset"  },
        { "OffhandOffset",  "SpawnInfoOffhandOffset"  },
    };
    for (const auto& s : spawnInfo)
    {
        ++total;
        DWORD val = (DWORD)ir_intf->readIntegerEntry("SpawnInfo Offsets", s.iniKey);
        bool  d32 = (val > 127);
        out << s.iniKey << " (0x" << std::hex << val << "):\r\n";
        auto hits = fpFindStructAccesses(textBuf, textSize, textRawOff, val);
        out << "  " << std::dec << hits.size() << " candidate(s)\r\n";
        if (fpWritePattern(exeData.data(), exeData.size(), textBuf, textSize, textRawOff,
                           hits, d32 ? 8 : 14, d32 ? 4 : 1, d32 ? 6 : 8, 't',
                           s.scanSec, ir_intf, out))
            ++found;
        SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
        UpdateWindow(hDlg);
    }
    out << "\r\n";

    // ---- WorldInfo patterns ----
    out << "[WorldInfo Patterns]\r\n";
    struct { const char* iniKey; const char* scanSec; } worldInfo[] = {
        { "WorldHourOffset",   "WorldInfoHourOffset"   },
        { "WorldMinuteOffset", "WorldInfoMinuteOffset" },
        { "WorldDayOffset",    "WorldInfoDayOffset"    },
        { "WorldMonthOffset",  "WorldInfoMonthOffset"  },
        { "WorldYearOffset",   "WorldInfoYearOffset"   },
    };
    for (const auto& w : worldInfo)
    {
        ++total;
        DWORD val = (DWORD)ir_intf->readIntegerEntry("WorldInfo Offsets", w.iniKey);
        bool  d32 = (val > 127);
        out << w.iniKey << " (0x" << std::hex << val << "):\r\n";
        auto hits = fpFindStructAccesses(textBuf, textSize, textRawOff, val);
        out << "  " << std::dec << hits.size() << " candidate(s)\r\n";
        if (fpWritePattern(exeData.data(), exeData.size(), textBuf, textSize, textRawOff,
                           hits, d32 ? 8 : 14, d32 ? 4 : 1, d32 ? 6 : 8, 't',
                           w.scanSec, ir_intf, out))
            ++found;
        SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
        UpdateWindow(hDlg);
    }

    out << "\r\nDone: " << std::dec << found << "/" << total << " patterns written.\r\n";
    SetDlgItemText(hDlg, IDC_EDIT2, out.str().c_str());
    return found > 0;
}