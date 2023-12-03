#include "./headerfiles/crypto/aes/aes.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "./headerfiles/crypto/rsa/scrsa.h"
#include "./headerfiles/hwinfo/hwinfo.h"
#include "./headerfiles/crypto/aes/aes.h"
#include <fstream>
#include "hardwareinfo.h"

std::string GetHardwareInfo(void)
{
	std::string hardwareInfoStr = sha1_hash(getinfo());

	if (hardwareInfoStr.empty())
	{
		std::cout << "Error: getinfo() failed." << std::endl;
		return 0;
	}
	std::string rsaPubKeyStr1 = "03";
	std::string rsaN1 = "9D1AC010576E5C151C4E806DF2F3490718FA808A33F83A01225CB300769B56111110297891129BC4C9B2E45BFAAA55DD74AFDBD7663A4DC5E60211FD035434D1E1F26CAD063D226A11E84BFD01E0AF8848C1CEE21D3BD7A6733A63128873D8B247B3498D15F261BA37EEA568024AF275055703B7B182906899C91D4089151FB0DFF6CA0D94FD9187FEA9CCA34A0199E9B85903E8EC420D69F037E869E6CEA4085B833853B180322A89437618EA1358A65E3ADDC71F72C43D74AD1755882D6E5CA7DAA1B83281F050127D0B685B16E81A37B247ECE4305253D0D30A3F7C7E88E74FFAC447E35A14554961A6ECEC825CA10CBF5ECCECF424CD9A1084A038797039";
	scrsa rsa;
	std::string binEncryptostr = rsa.encrypt_string(rsaPubKeyStr1, rsaN1, hardwareInfoStr);
	Dbgcout("hard info hash DEC 1:\n"
			<< hexToString(hardwareInfoStr) << std::endl);
	Dbgcout("crypt bin string DEC 1:\n"
			<< hexToString(binEncryptostr) << std::endl);
	std::ofstream outfile("./hardwareinfo.bin");
	outfile << binEncryptostr.c_str();
	DbgPrint(("source:[%d] target:[%d]\n",hardwareInfoStr.length(),binEncryptostr.length()));

	return binEncryptostr.c_str();
}

bool CheckHardwareInfo(std::string hashstring)
{
	std::string rsaPrivateKeyStr2 = "6C6A33735386AD9BA8CFA2AF77AD4E5668BFDB4EF61D6A2793D48ED90CF359C1878533CD3AED5568163F938695F3D641309A01750388F10A9562580367A74E4D3C81DDF4CB2B1F2CB4D63E5D8D08DCABEE2AD74803B53D2A11F841D35CB0336B53D9204150EFF0002932CF0DB1862C8F2FCF643666F2DC6446524FF3FD055DBBB5B1F5FF8CFA748E2057DBF91733D3DFBBEBDA89E32093E41C408DFBCF29FE3ED1680BE3569BD8B06740C26331ACD01887FA66CDA983EDFFBB331DCDCF12CC3AF6F559D20558D55B71E89DF790612149642F5BD5EAF8D052A35DBE5A38F03C1471D0537279579AEC022B293803ADBD045C6BDE704EF49CA03609E17A770EB9E3";
	std::string rsaN2 = "A29F4D2CFD4A04697D3774073383F5819D1FC8F6712C1F3B5DBED645936D06A24B47CDB3D864001C215F5D49E0EDC161C8E7022F854D698FE01384051B7AF573DAC2CCEF30C0AEC30F415D8C538D4B01E54042EC058FDBBF1AF462BD0B084D20FDC5B061F967E8003DCC36948A4942D6C7B716519A6C4A96697B77EDFB880C9B289FD9813DA7B2016E9877E748A6C101D991217F312B7DD0401355ED56BF318482D93C50B383135E98F5219A64D6D26946F698C1571F0548107249BFCA3E421E43959770B9A39A4CC13C2AAF00EC47D254BB4346C4B06A1A647D6CBF8DCA489D01E9F74C572066B9D51A983FD7B78354842E0A7B8D06B0B7FDD6ECF35CEE1DC1";

	// std::ifstream file(filepath);
	// if (!file) {
	//     std::cerr << "Error opening file." << std::endl;
	// }
	// std::string liecensefileStr((std::istreambuf_iterator<char>(file)),
	//                     std::istreambuf_iterator<char>());

	scrsa rsa;
	std::string encryptostr = rsa.decrypt_string(rsaPrivateKeyStr2, rsaN2, hashstring);
	Dbgcout("plain DEC 2:\n"
			<< hexToString(encryptostr) << std::endl);
	std::string hardwareInfoStr = sha1_hash(getinfo());

	Dbgcout("hard info hash DEC 2:\n"
			<< hexToString(hardwareInfoStr) << std::endl);

	if (encryptostr == hardwareInfoStr)
		return true;
	else
		return false;
}
