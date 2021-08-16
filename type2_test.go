package ntlmssp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestType2(t *testing.T) {
	bs, _ := hex.DecodeString("4e544c4d53535000020000000e000e003800000005828aa27061ee132005d5a4000000000000000058005800460000000a00614a0000000f5a0044004a002d0030003500310002000e005a0044004a002d0030003500310001000e005a0044004a002d0030003500310004000e007a0064006a002d0030003500310003000e007a0064006a002d00300035003100070008002d108a2e658ad70100000000")
	type2 := NewChallengeMsg(bs)
	//type2.Display()
	tinfo := ParseAVPair(type2.TargetInfo())
	for k, v := range tinfo {
		if k == "MsvAvTimestamp" {
			byteKey := []byte(fmt.Sprintf("%s", v.(interface{})))
			//fmt.Println(byteKey)
			i := binary.LittleEndian.Uint64(byteKey)
			i2 := i - 116444736000000000
			tm := time.Unix(0, int64(i2*100))
			v = tm
		}
		fmt.Printf("    %s: %v\n", k, v)
	}
}

func TestTime(t *testing.T) {
	//https://github.com/hirochachacha/go-smb2/blob/f071e13222d669bd071ff798608e85107d679e09/internal/ntlm/client.go#L237
	var timestamp []byte
	ft := uint64(time.Now().UnixNano()) / 100
	fmt.Println(ft)
	ft += 116444736000000000 // add time between unix & windows offset
	timestamp = make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, ft)
	fmt.Println(timestamp)

	i := binary.LittleEndian.Uint64(timestamp)
	i2 := i - 116444736000000000
	fmt.Println(i2)
	tm := time.Unix(0, int64(i2*100))
	fmt.Println(tm)
}
