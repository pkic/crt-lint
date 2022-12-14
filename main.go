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
	"sync"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	_ "github.com/zmap/zlint/v3/lints/apple
	_ "github.com/zmap/zlint/v3/lints/babf_brf_br"
	_ "github.com/zmap/zlint/v3/lints/ccbf__vev"
	_ "github.com/zmap/zlint/v3/lints/communityty"
	_ "github.com/zmap/zlint/v3/lints/tsi
	_ "github.com/zmap/zlint/v3/lints/mozillalla"
	_ "github.com/zmap/zlint/v3/lints/rfc
	"github.com/zmap/zlint/v3/test"

	"github.com/cloudflare/cfssl/revoke"
	_ "github.com/lib/pq"
)

type service struct {
	wgWrite    sync.WaitGroup
	wgWork     sync.WaitGroup
	writer     chan []string
	worker     chan []byte
	lintName   string
	lintConfig lint.Configuration
}

func (s *service) doWork() {
	for {
		der, more := <-s.worker
		if !more {
			s.wgWork.Done()
			return
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			log.Println(err)
			continue
		}

		result := test.TestLintCert(s.lintName, cert, s.lintConfig)
		if result.Status != lint.NA && result.Status != lint.Pass {
			gcert, err := gc.ParseCertificate(cert.Raw)
			if err != nil {
				log.Println("Failed to parse in native go")
				gcert = &gc.Certificate{}
			}
			revoked, ok, err := revoke.VerifyCertificateError(gcert)

			s.writer <- []string{
				fmt.Sprintf("https://crt.sh?sha256=%s", hex.EncodeToString(cert.FingerprintSHA256)),
				cert.ValidationLevel.String(),
				cert.Issuer.String(),
				strings.ToUpper(strings.Join(cert.Subject.Country, ", ")),
				cert.Subject.String(),
				cert.NotBefore.String(),
				cert.NotAfter.String(),
				result.Details,
				fmt.Sprintf("%t", revoked),
				fmt.Sprintf("%t", ok),
				fmt.Sprintf("%v", err),
			}
		}
	}
}

func (s *service) doWrite(w *csv.Writer) {
	for {
		line, more := <-s.writer
		if !more {
			w.Flush()
			s.wgWrite.Done()
			return
		}

		err := w.Write(line)
		if err != nil {
			log.Println(err)
		}
	}
}

func main() {
	var crtID int64
	var nw, batch int
	var filename, lintName string
	flag.Int64Var(&crtID, "offset", 0, "Last crt.sh ID processed")
	flag.IntVar(&nw, "workers", 10, "Number of concurrent worker")
	flag.IntVar(&batch, "batch", 1000, "Number of certificates to ask for per query")
	flag.StringVar(&filename, "out", "result.csv", "Output filename")
	flag.StringVar(&lintName, "lint", "", "Lint name (required)")

	flag.Usage = func() {
		fmt.Printf("usage: `%s [flags]`\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(lintName) == 0 {
		log.Fatal("a lint name must be provided with `-lint e_name_of_the_lint`")
	}

	p := message.NewPrinter(language.English)

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	writer := csv.NewWriter(f)
	defer f.Close()

	if crtID == 0 {
		err = writer.Write([]string{
			"crt.sh",
			"Validation",
			"Issuer",
			"Country",
			"Subject",
			"NotBefore",
			"NotAfter",
			"Error details",
			"Rev. revoked",
			"Rev. ok",
			"Rev. error",
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	s := service{
		writer:     make(chan []string, 10*nw),
		worker:     make(chan []byte, 100*nw),
		lintName:   lintName,
		lintConfig: lint.NewEmptyConfig(),
	}
	s.wgWrite.Add(1)
	go s.doWrite(writer)

	for i := 0; i < nw; i++ {
		s.wgWork.Add(1)
		go s.doWork()
	}

	total_processed := 0
	i := batch
	for i == batch {
		connStr := "postgres://guest@crt.sh/certwatch?port=5432&sslmode=disable&binary_parameters=yes"
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			log.Println(err)
			time.Sleep(1 * time.Minute)
			continue
		}
		defer db.Close()

		db.SetConnMaxLifetime(time.Second * 60)
		db.SetMaxOpenConns(1)

		// TODO: Add configurable query filters
		// AND (SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE) LIMIT 1) IS NOT NULL
		rows, err := db.Query(`SELECT c.ID, c.CERTIFICATE FROM certificate c WHERE 
				coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
				AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
				AND x509_hasExtension(c.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', TRUE)
				AND c.ID > $1
			ORDER BY c.ID
			LIMIT $2`, crtID, batch)
		if err != nil {
			log.Println("in query:", err)
			time.Sleep(1 * time.Minute)
			continue
		}
		defer rows.Close()
		p.Printf("Query completed (for crt.sh ID > %d)\n", crtID)

		i = 0
		for rows.Next() {
			i++
			var der []byte
			if err := rows.Scan(&crtID, &der); err != nil {
				log.Println(err)
				continue
			}

			s.worker <- der
		}

		total_processed += i
		p.Printf("Processed %d (up to crt.sh ID %d)\n", i, crtID)
		p.Printf("[%s] Total Processed: %d\n", time.Now().Format("2006-01-02 15:04:05"), total_processed)

		if err := rows.Err(); err != nil {
			p.Printf("[%s] in row %d: %s", time.Now().Format("2006-01-02 15:04:05"), i, err)
			time.Sleep(1 * time.Minute)
			i = batch
		}
	}

	close(s.worker)
	fmt.Println("Waiting on worker(s) to finish")
	s.wgWork.Wait()
	close(s.writer)
	fmt.Println("Waiting on writer to finish")
	s.wgWrite.Wait()
	fmt.Println("Done")
}
