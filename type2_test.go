package ntlmssp

import (
	"encoding/hex"
	"testing"
)

func TestType2(t *testing.T) {
	bs, _ := hex.DecodeString("4e544c4d53535000020000000e000e003800000005828aa22387abd57401dd74000000000000000058005800460000000a00614a0000000f4600580059002d0034003400320002000e004600580059002d0034003400320001000e004600580059002d0034003400320004000e006600780079002d0034003400320003000e006600780079002d0034003400320007000800c670163e5088d70100000000")
	type2 := NewChallengeMsg(bs)
	type2.Display()
}