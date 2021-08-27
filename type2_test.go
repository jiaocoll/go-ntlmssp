package ntlmssp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestType2(t *testing.T) {
	bs, _ := hex.DecodeString("4e544c4d53535000020000001e001e003800000005828aa25c0f5dfc015710c7000000000000000094009400560000000501280a0000000f5700570057002d003900460034003600380033004600430045003500420002001e005700570057002d003900460034003600380033004600430045003500420001001e005700570057002d003900460034003600380033004600430045003500420004001e007700770077002d003900660034003600380033006600630065003500620003001e007700770077002d0039006600340036003800330066006300650035006200060004000100000000000000")
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
		fmt.Printf("%s: %v\n", k, v)
	}
	offset_version := 48
	version := bs[offset_version : offset_version+8]
	v, _ := ReadVersionStruct(version)
	fmt.Println(v)
}

func TestChallengeMsg_String(t *testing.T) {
	bs, _ := hex.DecodeString("4e544c4d53535000020000001e001e003800000005828aa25c0f5dfc015710c7000000000000000094009400560000000501280a0000000f5700570057002d003900460034003600380033004600430045003500420002001e005700570057002d003900460034003600380033004600430045003500420001001e005700570057002d003900460034003600380033004600430045003500420004001e007700770077002d003900660034003600380033006600630065003500620003001e007700770077002d0039006600340036003800330066006300650035006200060004000100000000000000")
	type2 := ChallengeMsg{}
	info := type2.String(bs)
	fmt.Println(info)
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
