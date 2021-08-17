package ntlmssp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestType2(t *testing.T) {
	bs, _ := hex.DecodeString("4e544c4d53535000020000001e001e003800000005828aa2d198a2c268cae15c000000000000000098009800560000000a00614a0000000f530043002d0032003000320031003000350031003800310035003400360002001e00530043002d0032003000320031003000350031003800310035003400360001001e00530043002d0032003000320031003000350031003800310035003400360004001e00530043002d0032003000320031003000350031003800310035003400360003001e00530043002d0032003000320031003000350031003800310035003400360007000800b98179572b93d70100000000")
	type2 := NewChallengeMsg(bs)

	//tinfo := ReadAvPairs(type2.TargetInfo())
	//fmt.Println(tinfo)
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
	offset_version := 48
	version := bs[offset_version : offset_version+8]
	v, _ := ReadVersionStruct(version)
	fmt.Println(v)
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
