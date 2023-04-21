package rsa

import (
	"encoding/hex"
	"github.com/gogf/gf/v2/os/gctx"
	"testing"
)

func TestGenerateRSAKeypair(t *testing.T) {
	prikey, pubkey, err := GenerateRSAKeypair(gctx.New())
	if err != nil {
		t.Fatal(err.Error())
	}
	hexPrikey := hex.EncodeToString(prikey)
	hexPubkey := hex.EncodeToString(pubkey)
	t.Log(hexPrikey)
	t.Log(hexPubkey)
}

func TestEncryptRSA(t *testing.T) {
	//prikey := "308204a40201000282010100dd3eea13494d61124df8764f499a8e6dd6ed75eb07095543f25de1af8f0b5e98f9feafa77a0a37b7b0c5679871deb79d9db3d3c163996f7f0abef88af9de08c7dda87fd3f578c00102d6ed15fb24846fcab6f99c53e265804ca6404353eb851d53f245dd574ad0aaf832ee2c968ed0da35968bb10ad0db2d0b470f9e548a2c3b8451c88c7a0e4d6f2e4d9c8758656c8ec6d71c1755aa4dde8799b3bd46e6277bfb810c57e8961c11d8b507d6c6ef8907743a88a35014878ea2a4dda1f8164aaf6c84c3163f1eef5466fb0b8cc5e1cd31a1a2a8ef4b98ded4b031b767069669c8e78b1d56770e798866474a3ad988860b9b6f0d5f9c3497cb7d0e9c2ee5d2c5e102030100010282010064ac251ce384f73fba04ede8c42834d91c2c6f34a3be0673658c7c8e42fbbc6ec58ab368f4aa43922d38961c12ec7206a164db5d2b31fd3f04a7c33691de0b86ce80c6b1af07e3ee51d974864501e7d56a9b79d73d804e0964575df484f22d5f1bfca8f7bfa9c66b9586af43d0ba69a4712ff09e7dba6d910089b43caa6139207f3f1c20a6971e5e2f49e9505d6c873d2df3032c2df8fe52fee6f342ef7bb9ce88e9e5dddfea8c4deec53e9158812ef361b4931e806afeb4ba1d896a553a48cd7b5e88c73123a7ffbd6714a6bf036cf43c58d25d3a1dd71f6ee8a71e84c78678f8524893f4c51c3b6107dbe55b9dfe401535c1f53704110cb05805130d0a19c502818100e87e99ba34bbf646fad298608f7019963cd4f6b47323ebc6a0f4843860ec4528d414a78409f01b6cca9add32cdbc86bf22b477ed036c1da5bee3381d93293216714d4159bd7805df7a22da1f0f79bde14ee4815d286a1e7390f563fd19a874c4632c2d497e7b89d7ee97a27d7354abd0419293dab27a27a516aff79d0256e13302818100f39d2c9bcde0cd2ef7faebc077cad0f807eefe2b9dc2dbdb55c16f9cc630bed7b5e3933aa557c968582f7641bd60a62a55e6f5ed79f21a3af3725d172445448d7133eacbe6367862dc1d60237c1945640a12f48d6b9e570d9a44cc6dc3800568eeb039c80683c471d97ab704bb83495750c7b73e0c37f5fc3cddaa37c8bde49b02818100d1ffe86324d6d270f285de54f9bacba1c478a80dfe22680915c146dc95cf53f8b8f79f07c8e23423642dd5b6d9d67bef912d6955904dcbc9b64e0e95c822e1b71bc8284b22b492b974dc9e20881df2c0dc3dd20b8f41ab17bfcba6f12a87da50b93362048c5691ff94e72a421e3650aadf4fc2753bd8d28e6f9baa110bd7e5b902818100aff9d098779eb4f901beeaffac4900acbaa6644a437ad7f057c1148bee0a9641222dd353a0ce8a39eac1d62de4cbe51c5dd329c132beb53df24fa1792f052e60f1ee2be4c056869dfb1ce92e98dd7467b07342dec967a6c0b7b88ce7993a682e05859d27a5b517799a3cefe9e63e0f0398e1bbb781820719ff29ac650188529302818019d10053dfbc0c550a325eac4b1d6d10f6127e6f967fcaa00ac82135ea534de98f8e012be306852a43f371bb67f2c12a13e3ba143447dd37bb2a0471345ca720745cad4fb0173fad8d54e5c18515e6f3ef600bc733a95a26fe58e604adc07882950452422b3687a84baff6365346ef5397ee8382a068a8d1e5cd3cfbee959085"
	pubkey := "3082010a0282010100dd3eea13494d61124df8764f499a8e6dd6ed75eb07095543f25de1af8f0b5e98f9feafa77a0a37b7b0c5679871deb79d9db3d3c163996f7f0abef88af9de08c7dda87fd3f578c00102d6ed15fb24846fcab6f99c53e265804ca6404353eb851d53f245dd574ad0aaf832ee2c968ed0da35968bb10ad0db2d0b470f9e548a2c3b8451c88c7a0e4d6f2e4d9c8758656c8ec6d71c1755aa4dde8799b3bd46e6277bfb810c57e8961c11d8b507d6c6ef8907743a88a35014878ea2a4dda1f8164aaf6c84c3163f1eef5466fb0b8cc5e1cd31a1a2a8ef4b98ded4b031b767069669c8e78b1d56770e798866474a3ad988860b9b6f0d5f9c3497cb7d0e9c2ee5d2c5e10203010001"
	plaintext := "helloworld"
	rawpub, err := hex.DecodeString(pubkey)
	if err != nil {
		t.Fatal(err.Error())
	}
	result, err := EncryptRSA(gctx.New(), []byte(plaintext), rawpub)
	if err != nil {
		t.Fatal(err.Error())
	}
	newResult := hex.EncodeToString(result)
	t.Log(newResult)
}

func TestDecryptRSA(t *testing.T) {
	ciphertext := "a5aefe287f2bd619573d50376bae1446f3ad3081e6a5afb87d2d6ecb0d01aad2c87f61379956950c4a65236a639e7e35bf1eb2efb410c32964e2da168d57f8e6c42f0c14be0872dca3d431c5da6092d2ed363c26111e9e642e94b6121f7fbf849b600973ed53949ce194200dd738a4d27a4c37c3b277c7bdb665f95d2e94921327a15605581b17dd2d701400a71a6d507e788cef84195a60bafb0f348b55dfca91165475ef2f85164e707933558ae483c663a0437965760edcef1141b2b1bff6a274a135260cc07be8215dc24b011e53a53d9588c195522b8d3e6a8b32b01a6dc38add7c55385caced5f6d236f3432ede3d13c7a9ef12ca0fff169db39490dc4"
	prikey := "308204a40201000282010100dd3eea13494d61124df8764f499a8e6dd6ed75eb07095543f25de1af8f0b5e98f9feafa77a0a37b7b0c5679871deb79d9db3d3c163996f7f0abef88af9de08c7dda87fd3f578c00102d6ed15fb24846fcab6f99c53e265804ca6404353eb851d53f245dd574ad0aaf832ee2c968ed0da35968bb10ad0db2d0b470f9e548a2c3b8451c88c7a0e4d6f2e4d9c8758656c8ec6d71c1755aa4dde8799b3bd46e6277bfb810c57e8961c11d8b507d6c6ef8907743a88a35014878ea2a4dda1f8164aaf6c84c3163f1eef5466fb0b8cc5e1cd31a1a2a8ef4b98ded4b031b767069669c8e78b1d56770e798866474a3ad988860b9b6f0d5f9c3497cb7d0e9c2ee5d2c5e102030100010282010064ac251ce384f73fba04ede8c42834d91c2c6f34a3be0673658c7c8e42fbbc6ec58ab368f4aa43922d38961c12ec7206a164db5d2b31fd3f04a7c33691de0b86ce80c6b1af07e3ee51d974864501e7d56a9b79d73d804e0964575df484f22d5f1bfca8f7bfa9c66b9586af43d0ba69a4712ff09e7dba6d910089b43caa6139207f3f1c20a6971e5e2f49e9505d6c873d2df3032c2df8fe52fee6f342ef7bb9ce88e9e5dddfea8c4deec53e9158812ef361b4931e806afeb4ba1d896a553a48cd7b5e88c73123a7ffbd6714a6bf036cf43c58d25d3a1dd71f6ee8a71e84c78678f8524893f4c51c3b6107dbe55b9dfe401535c1f53704110cb05805130d0a19c502818100e87e99ba34bbf646fad298608f7019963cd4f6b47323ebc6a0f4843860ec4528d414a78409f01b6cca9add32cdbc86bf22b477ed036c1da5bee3381d93293216714d4159bd7805df7a22da1f0f79bde14ee4815d286a1e7390f563fd19a874c4632c2d497e7b89d7ee97a27d7354abd0419293dab27a27a516aff79d0256e13302818100f39d2c9bcde0cd2ef7faebc077cad0f807eefe2b9dc2dbdb55c16f9cc630bed7b5e3933aa557c968582f7641bd60a62a55e6f5ed79f21a3af3725d172445448d7133eacbe6367862dc1d60237c1945640a12f48d6b9e570d9a44cc6dc3800568eeb039c80683c471d97ab704bb83495750c7b73e0c37f5fc3cddaa37c8bde49b02818100d1ffe86324d6d270f285de54f9bacba1c478a80dfe22680915c146dc95cf53f8b8f79f07c8e23423642dd5b6d9d67bef912d6955904dcbc9b64e0e95c822e1b71bc8284b22b492b974dc9e20881df2c0dc3dd20b8f41ab17bfcba6f12a87da50b93362048c5691ff94e72a421e3650aadf4fc2753bd8d28e6f9baa110bd7e5b902818100aff9d098779eb4f901beeaffac4900acbaa6644a437ad7f057c1148bee0a9641222dd353a0ce8a39eac1d62de4cbe51c5dd329c132beb53df24fa1792f052e60f1ee2be4c056869dfb1ce92e98dd7467b07342dec967a6c0b7b88ce7993a682e05859d27a5b517799a3cefe9e63e0f0398e1bbb781820719ff29ac650188529302818019d10053dfbc0c550a325eac4b1d6d10f6127e6f967fcaa00ac82135ea534de98f8e012be306852a43f371bb67f2c12a13e3ba143447dd37bb2a0471345ca720745cad4fb0173fad8d54e5c18515e6f3ef600bc733a95a26fe58e604adc07882950452422b3687a84baff6365346ef5397ee8382a068a8d1e5cd3cfbee959085"
	rawCipherText, err := hex.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err.Error())
	}
	rawPrikey, err := hex.DecodeString(prikey)
	if err != nil {
		t.Fatal(err.Error())
	}
	result, err := DecryptRSA(gctx.New(), rawCipherText, rawPrikey)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(string(result))
}
