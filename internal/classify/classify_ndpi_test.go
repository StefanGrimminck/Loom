//go:build ndpi

package classify

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Real first-payloads captured by the honeypots (from honeylabs.ecs_logs), each
// a protocol the old ClickHouse rules left unclassified. Verifies nDPI labels
// them and that the label is stable, so a libndpi upgrade that changes a name
// is caught here rather than silently in production.
func TestClassifyKnownPayloads(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name    string
		dstPort uint16
		hexPay  string
		want    string // substring expected in the lowercased label; "" = must stay blank
	}{
		{"bittorrent", 39131, "13426974546f7272656e742070726f746f636f6c00000000001800051bba521fdbc6b84ea3119a59eb71177f7c4fbc3c2d5557313630392d4d494344", "bittorrent"},
		{"mssql", 1433, "1201003400000000000015000601001b000102001c000c0300280004ff080001550000004d5353514c53657276657200bc0a0000", "mssql"},
		{"rtsp", 8554, "444553435249424520727473703a2f2f3139322e302e322e31303a383535342f53747265616d696e672f4368616e6e656c732f31303120525453502f312e300d0a435365713a2034370d0a557365722d4167656e743a204c61766636302e332e31", "rtsp"},
		// SMB is deliberately blank: nDPI 4.2 only resolves this negotiate
		// packet by PORT (Match by port), which we reject as a guess. The old
		// rules didn't catch it either. Honest blank beats a port guess.
		{"smb_port_only", 445, "00000045ff534d4272000000001801c8000000000000000000000000ffff000000000000002200024e54204c4d20302e31320002534d4220322e3030", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pay, err := hex.DecodeString(tc.hexPay)
			if err != nil {
				t.Fatalf("hex: %v", err)
			}
			got := c.Classify(pay, TCP, 40000, tc.dstPort)
			if tc.want == "" {
				if got != "" {
					t.Errorf("Classify() = %q, want blank (port-only guess must be rejected)", got)
				}
			} else if !strings.Contains(got, tc.want) {
				t.Errorf("Classify() = %q, want substring %q", got, tc.want)
			}
		})
	}
}

// Guard against the flow-cache contamination bug: classifying one protocol must
// not bleed its label onto the next unrelated payload.
func TestClassifyNoContamination(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	bt, _ := hex.DecodeString("13426974546f7272656e742070726f746f636f6c00000000001800051bba521fdbc6b84ea3119a59eb71177f7c4fbc3c2d5557313630392d4d494344")
	rtsp, _ := hex.DecodeString("444553435249424520727473703a2f2f3139322e302e322e31303a383535342f53747265616d696e672f4368616e6e656c732f31303120525453502f312e30")
	// Alternate them; each must classify as itself, never inherit the other.
	for i := 0; i < 200; i++ {
		if got := c.Classify(bt, TCP, 40000, 39131); got != "" && !strings.Contains(got, "bittorrent") {
			t.Fatalf("bittorrent bled to %q at i=%d", got, i)
		}
		if got := c.Classify(rtsp, TCP, 40000, 8554); strings.Contains(got, "bittorrent") {
			t.Fatalf("rtsp returned bittorrent (contamination) at i=%d", i)
		}
	}
}

// Empty and junk payloads must never crash and must classify as "".
func TestClassifyEdgeCases(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.Classify(nil, TCP, 1, 2); got != "" {
		t.Errorf("nil payload = %q, want empty", got)
	}
	if got := c.Classify([]byte{0x00}, TCP, 1, 2); got != "" {
		t.Errorf("1-byte junk = %q, want empty", got)
	}
}

// Hammer the classifier to shake out leaks / double-frees in the per-call
// flow malloc/free path. Run with -race for concurrency safety.
func TestClassifyStress(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pay, _ := hex.DecodeString("13426974546f7272656e742070726f746f636f6c")
	for i := 0; i < 20000; i++ {
		_ = c.Classify(pay, TCP, 40000, 39131)
	}
}

// UDP payloads must be classified as UDP. Before transport awareness both were
// wrapped in a TCP header, where nDPI's DNS dissector expects a length prefix
// and its QUIC dissector does not run at all.
func TestClassifyUDPPayloads(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name    string
		dstPort uint16
		hexPay  string
		want    string
	}{
		{"dns query", 53, "abcd01000001000000000000076578616d706c6503636f6d0000010001", "dns"},
		{"quic initial (curl, ngtcp2)", 443, "c60000000114953ac9e3a9eb41964ff4cc290401bdee43c5f375148bd3b93123596eec8dff3e629a2a16d8bc046caa008000047c7f389a92ae6f5aef3343480f8f924f301f8e7b9168ad9194dd53ebae21dd3028781eedace8d5136625841d8daf4b669bd7dcf595b48938518dbcf5ea8a2b1adc020b6ab8ebdfb9611a82e1f21192237aaaa4cc7581023d284622a223be8d97d1e5725836e30443ee83c2da4bee5457e3af92855feec68d29a1f5dc148a4838388a120b425bfeed6b3d20793e746f4fa260ab272c2ef36c34a4326316695b60860dbfedcc84b8ae6623c492357e12e780cbf4872cf95e359523dab24da345fa9deeef490a3a414987485cfe16816b7fcbd5901d9ea948e9ff93bbcc1363ec36eb767732dffa27a21b9983eb2cd04590afae33245bfcbccb35092a6061f07807ce6ce9434c332b7cf8711a27a1ec2f633f568fae7834137e3fc327892b9ca1b3c7ee8eb07658ff9c61ee24f5918405b2ae7dcfc8f1f6894347a3de902e8ab2e3dfdbb6b99fccb7640abb9f0c7887699c885e55985d3d89eb2b828b591e84d1344c766eac3cf10a9f74a6a869c52122dd1dd58d6aca88cf50454451432d026172e75b44a6b1af625074c150aec4db6b3846c3b161c3266e981906813aab78291400e25c7c7c4e8b13a4c5f72323dfce8fcc31d29359eabcdcef7b9130ea495b0b967dfc51c1c3b4d404ef5e61b650a42cc1cc7ea4c3acbd8413c8f33b75f56343a9be67bdb2a6cb045b9726b5c1cf46713c3df21b2a3a251758da09b759c4bdb3754a3e7f5bdd2d0c281ac9a5388ae742a7ef179f24f5d7dbad67be2311d7c91b108904f070e6af329203636f73fac60d2d8c63a0fd79769a76e4b8c8ef37ea5caafc9674bd2b11ad737d37908271dd238c5637f1f01f21757b75878cfe1a74d10d2bb560bfe0b800ad670f131a3ac5bcd66ceb4b95b305ebbed100bbedbd2a073cfb12b52809d3e3443a37c453ab0778762b09b2c726dcd96feb09fd59ea3d318200dda0b971775e794ec6c8f95d7181f33c55a7f103139fe01be541889d9cd94c9e1737e5b53dbefe8b9e9d12ea6ae1a49fe5f51cba46e93e804e8bde6a825d745478e2d19df077eeeb3267b18251a626ae68430091a30544eb1ab19906db7fa5b9de865f8dd9f5a531825c4266b0f22f704d54ef3ad9b47f1482bec50f6e935ba79f0508c6c3b6d3f5f738c726f2212969febd34cf4981789fd93075790e8701419ba6fe9474a0d316f34a81e3c142c3f38187398f459cc5ccc164fddbb4ec9b37f1a2719c1a242215e4cbc897352467cddb1c4273b49e48acd2b95abd89ce53420ac8ce0f88f076d99c8cdb1a910c5a5456dd7ba9fb18aee38510f4046755fbad5435a53d011c699eedd83ca4078f72df0d922b68ce1a21ceb95a7b7bb9f5aa9655af5e5d71ec1bf73554d65ec27ca423f367472410b0192681e6a3489c21ec9a350b7115272445526a506b8b088add9c7a2838840a1341f0864399e23d390bba940fc88f06a9e4bc0988a71bf3dbe8cb4d86850a59b1a3730121122a2493555d60364abc58b4d3f08375e7631492a90824a1b2a3b54549b00360f00710a4ae67765308412784bd731b8c057bc7037e245c185ddf783e4e94db073666df1836ca434d8bc931976b76f38dcb11cfc3733b74ec005abca40ba5ad800fce0000000114953ac9e3a9eb41964ff4cc290401bdee43c5f375148bd3b93123596eec8dff3e629a2a16d8bc046caa008000047c957f47aab0f7c9853e391cf5c0a6fa91972f97e631ad6fdc831246af0da3b82ba0143248e72efad9e3fc61924675ea9f3954ed459906eccd0f1a58e7ea94773eefa5727a0aeb72c787af66569a08f5cc0b78d346a3ff8d1718751045263b4995d0cb68d1701a8f0ca464c15994693304d79c4bc6b7c8bc25d651873a5cb96768996398b68f19bb4e079062f0e097d1f326a9b5d8fd0bb1c2b1cca5c8387e81ae79f8c391a9d42cfe7f761aa4d3ba3bc03482697967577314f95372743fc7a6142310273a0e86cdcec6b7e86fa2838ee4e93a4fffbc6cc459a236387de2db65c08330de90855f6fc935c9d4a4c50bf262ebaa26c3fca4f979ba796eec9698c92e78ee22c1ef944eccfc902d7d73ed61bcc3fbe4c99fd51b8309cd4044e12976a902920e0bdef26645c3bcaf438c2249da40bbb28829ee33409c30603b36fab7cdb94a96dbff88335827ece800d2d802661bf662f0446388c9cd32c59761130270598e95bf780d48ace7bfbfde5571b82a3564ffaf36769ab7259d76fa5de8e0c4ececf851607e47d9d349a24910a1d959d05a37e505f206d75fe0f8a977a351dcc47b9f5e5492f48377fbff7cc2f7fdf15e1d11e89b811b06617239cc1d625733a00b75361ae0e139eb7faf1a0bfcf3f6abc01c844919c451d67c7d4a334326c8cf5940ef88cb0716554878f23835e5a830048718d0c40e81def758d222f6bf44924755562f718df62e20c99c831019e2db7e5f81b6577a4f945ad47434e02c5b852a198a508668bfb8f93922b5b1194d464bb291b9346b28e91d24928461d9abc4ad9c9458f6770c9012b433bca98611d3364ec0d5ecc4673658a22e5a24628b8321d26e0e33722d7fc3df6b074e4814eb5ca33990aa3bbd5ae8020f222d5f8f948274174dc86ea781365436fecb74f5d2e1eadb5b5a2adee602a2ca135ceafccebba6f9611a43411ca7adc50dbebf3f32dee272116daf2a6ab28a263a843b115a26d4c313b75dc28a0690fcc7b3899e1795fd760f805c67c6d9742b68b64d264c589bf6fd2a0f7e45dfe019c5dff32fb2f5d84e7d540bbe88beffdafd45a2434f9f603acf7fe54502f945cab65a4499fef98ba7022ad6bbfe2f78cd1a80771c65c513db2438ea89274aca88ccb40dd8556e305806fc204fe4e6ab34dc542a290c1ffbd1d3370c0d62644ecfdd2bc158b1c64ee765fa71d40cc0778a71ecc3b4338076fdbc81a428849c10de3c62ea07ed31d49edf7e07a90fb7a580c76344e6b1d6b159783a34fe8902f6a65013a2ca0fa93fca7ee81d22ed0aca873e0213974b08169ec99258d810e722124c9d1e7c046c25870664e4fd994faa55d08ffa7fc58230819589b17ba8c62bc2bd435c887ad56bf61b2d0498568dd6a6c570fb923c756c4e3c8ac2fc46793dfe21da7db6f31b208cd511452fd404389004e6429cbf9b292f5d54304498612106f9db7a4e1008f0c80422375cd8481e17409150173f06fdb97887f6b2fb70eb5ebb50e2759e6e5e891a2f1962e8144f6cad14d1fcd09dd83f563caae70becd7ce007a64da8b034e78527e4419b0822ad9b02a82c3e6e1467449acb4d74f767f0e89f6144bb47c8498dcdeb287d8fce8ba", "quic"},
	}
	for _, tc := range cases {
		pay, err := hex.DecodeString(tc.hexPay)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Classify(pay, UDP, 40000, tc.dstPort); !strings.Contains(got, tc.want) {
			t.Errorf("%s over UDP = %q, want %q", tc.name, got, tc.want)
		}
	}
}
