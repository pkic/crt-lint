package main

import (
	gc "crypto/x509"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	_ "github.com/zmap/zlint/v3/lints/community"
	"github.com/zmap/zlint/v3/test"

	"github.com/cloudflare/cfssl/revoke"
	_ "github.com/lib/pq"
)

func main() {
	var i uint64
	var filename string
	flag.Uint64Var(&i, "offset", 0, "Records to skip")
	flag.StringVar(&filename, "out", "result-regions.csv", "Output filename")

	flag.Usage = func() {
		fmt.Printf("usage: `%s [flags]`\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	writer := csv.NewWriter(f)
	defer f.Close()

	if i == 0 {
		writer.Write([]string{
			"Count",
			"crt.sh",
			"Validation",
			"Issuer",
			"Country",
			"Province",
			"Subject",
			"NotBefore",
			"NotAfter",
			"Rev. revoked",
			"Rev. ok",
			"Rev. error",
		})
	}

	for {
		connStr := "postgres://guest@crt.sh/certwatch?port=5432&sslmode=disable&binary_parameters=yes"
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			log.Println(i, err)
			time.Sleep(1 * time.Minute)
			continue
		}

		db.SetConnMaxLifetime(time.Second * 60)

		rows, err := db.Query(`SELECT c.CERTIFICATE FROM certificate c WHERE 
				coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
				AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
				AND (SELECT x509_nameAttributes(c.CERTIFICATE, 'stateOrProvinceName', TRUE) LIMIT 1) IS NOT NULL
			OFFSET $1`, i)
		if err != nil {
			log.Println("in query", i, err)
			db.Close()
			time.Sleep(1 * time.Minute)
			continue
		}
		log.Println("Query completed", i)

		for rows.Next() {
			i++
			if i%10000 == 0 {
				log.Println(i)
			}

			var der []byte
			if err := rows.Scan(&der); err != nil {
				log.Println(err)
				continue
			}

			cert, err := x509.ParseCertificate(der)
			if err != nil {
				log.Println(err)
				continue
			}

			if len(cert.Subject.Province) == 0 {
				continue
			}
			result := test.TestLintCert("n_subject_state_unknown", cert)
			if result.Status != lint.NA && result.Status != lint.Pass {
				gcert, err := gc.ParseCertificate(cert.Raw)
				if err != nil {
					log.Println("Failed to parse in native go")
					gcert = &gc.Certificate{}
				}
				revoked, ok, err := revoke.VerifyCertificateError(gcert)

				writer.Write([]string{
					fmt.Sprintf("%d", i),
					fmt.Sprintf("https://crt.sh?sha256=%s", hex.EncodeToString(cert.FingerprintSHA256)),
					cert.ValidationLevel.String(),
					cert.Issuer.String(),
					strings.ToUpper(cert.Subject.Country[0]),
					cert.Subject.Province[0],
					cert.Subject.String(),
					cert.NotBefore.String(),
					cert.NotAfter.String(),
					fmt.Sprintf("%t", revoked),
					fmt.Sprintf("%t", ok),
					fmt.Sprintf("%s", err),
				})
			}
		}

		writer.Flush()
		fmt.Println("Total processed:", i)

		if err := rows.Err(); err != nil {
			log.Println("in row", i, err)
			db.Close()
			time.Sleep(1 * time.Minute)
			continue
		}
		break
	}
}
