// Inert test sample: it only *contains* strings typical of malware so that
// binchk's detections can be exercised. It performs no actions.
package main

import (
	"fmt"
	"os"
)

var indicators = []string{
	"vssadmin delete shadows /all /quiet",
	"Your files have been encrypted! To decrypt your files, buy bitcoin",
	"stratum+tcp://pool.invalid:3333",
	"http://45.77.10.20/stage2.bin",
	"https://discord.com/api/webhooks/000/test",
	"BraveSoftware\\Brave-Browser", "Yandex\\YandexBrowser", "Chromium\\User Data",
	"Google\\Chrome\\User Data", "BraveSoftware", "Microsoft\\Edge\\User Data", "Opera Software", "Vivaldi",
	"Login Data", "logins.json", "key4.db", "encrypted_key",
	"wallet.dat", "Exodus\\exodus.wallet", "Electrum\\wallets", "nkbihfbeogaeaoehlefnkodbefgpgknn",
	"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
	"xattr -d com.apple.quarantine", "display dialog", "with hidden answer",
}

func main() {
	if len(os.Args) > 99 {
		fmt.Println(indicators)
	}
}
