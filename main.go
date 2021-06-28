package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/tealeg/xlsx"
)

type Plugin struct {
	Plugin   string `json:"Plugin"`
	Infected bool   `json:"infected"`
	Error    string `json:"error"`
}

type Response struct {
	Response         []Plugin `json:"response"`
	PercentageOfRisk string   `json:"percentageOfRisk"`
	FileBody         FileBody `json:"file_body"`
}

type FileBody struct {
	Sha1 string `json:"sha1"`
	Size string `json:"size"`
}

var port, dir, filename string

func init() {
	initFlag()

	flag.Parse()
}

func initFlag() {
	flag.StringVar(&port, "port", "5000", "")
	flag.StringVar(&dir, "dir", ".", "")
	flag.StringVar(&filename, "name", "test.xlsx", "")
}

func main() {

	url := "http://localhost:" + port + "/scan"
	method := "POST"
	exclFile := xlsx.NewFile()

	sheet, err := exclFile.AddSheet("sheet 1")
	if err != nil {
		panic("error excel sheet: " + err.Error())
	}
	if err := sheet.SetColWidth(0, 0, 30); err != nil {
		panic("error sheet width " + err.Error())
	}

	if err := sheet.SetColWidth(1, 11, 30); err != nil {
		panic("error sheet width " + err.Error())
	}

	header := sheet.AddRow()
	header.Height = 11
	styl := xlsx.NewStyle()

	styl.Font.Bold = true
	styl.Font.Size = 11

	styl.Alignment.Horizontal = "center"
	styl.ApplyAlignment = true
	styl.ApplyFont = true
	cell := header.AddCell()
	cell.SetStyle(styl)

	cell.Value = "file Sha1"
	cell.Merge(0, 1)

	cell = header.AddCell()
	cell.SetValue("Size")
	cell.SetStyle(styl)

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("ResponseTime")

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("detection rate")

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("deweb(malware,error)") //1

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("comodo(malware,error)") //2

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("fprot(malware,error)") //3

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("windwos defender(malware,error)") //4

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("escan(malware,error)") //5

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("fsecure(malware,error)") //6

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("clameav(malware,error)") //7

	cell = header.AddCell()
	cell.SetStyle(styl)

	cell.SetValue("avira(malware,error)") //8

	row2 := sheet.AddRow()
	row2.Height = 11

	files, err := ioutil.ReadDir(dir)

	if err != nil {
		panic("error read dir :" + err.Error())
	}

	totalSize := float64(0)
	totalResponseTime := float64(0)
	avgc := 0.0
	zonerc := 0.0
	fprotc := 0.0
	windowsDefenderc := 0.0
	escanc := 0.0
	mcafeec := 0.0
	clamavc := 0.0
	avirac := 0.0
	avge := 0.0
	zonere := 0.0
	fprote := 0.0
	windowsDefendere := 0.0
	escane := 0.0
	mcafeee := 0.0
	clamave := 0.0
	avirae := 0.0

	totalCount := len(files)

	for i, f := range files {
		if f.IsDir() {
			totalCount--
			fmt.Println(i+1, " of ", len(files), " is dir .")
			continue
		}
		payload := &bytes.Buffer{}
		writer := multipart.NewWriter(payload)
		file, errFile1 := os.Open(dir + "/" + f.Name())
		if errFile1 != nil {
			panic("error open file : " + errFile1.Error())
		}
		part1, errFile1 := writer.CreateFormFile("file", filepath.Base(f.Name()))
		_, errFile1 = io.Copy(part1, file)
		if errFile1 != nil {

			panic("error io copy : " + errFile1.Error())
		}
		_ = writer.WriteField("token", "12")
		err = writer.Close()
		if err != nil {
			panic("error write close : " + err.Error())
		}

		client := &http.Client{}
		req, err := http.NewRequest(method, url, payload)

		if err != nil {
			panic("create request : " + err.Error())
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())
		t := time.Now()
		res, err := client.Do(req)
		if err != nil {
			panic("send request" + err.Error())
		}
		tdif := time.Now().Sub(t).Seconds()

		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			panic("error read : " + err.Error())
		}

		resp := new(Response)

		if err := json.Unmarshal(body, &resp); err != nil {
			fmt.Println(body)
			panic("error unmarshal : " + err.Error())
		}

		tmp, err := strconv.ParseFloat(resp.FileBody.Size, 64)
		if err != nil {
			fmt.Println("error file size (" + resp.FileBody.Size + ") : " + err.Error())
		}

		totalSize += tmp

		totalResponseTime += tdif

		row := sheet.AddRow()
		stylee := xlsx.NewStyle()
		stylee.Alignment.Horizontal = "center"
		stylee.ApplyAlignment = true

		cell := row.AddCell()
		cell.SetStyle(stylee)
		cell.SetValue(resp.FileBody.Sha1)

		cell = row.AddCell()
		cell.SetStyle(stylee)

		if tmp > 1000000 {
			cell.SetValue(fmt.Sprintf("%.2fMB", (tmp)/(1000000)))

		} else {
			cell.SetValue(fmt.Sprintf("%.2fKB", (tmp)/(1000)))

		}

		cell = row.AddCell()
		cell.SetStyle(stylee)

		cell.SetValue(math.Round(tdif))

		cell = row.AddCell()
		cell.SetStyle(stylee)

		cell.SetValue(resp.PercentageOfRisk)

		avg := row.AddCell()
		avg.SetStyle(stylee)

		zoner := row.AddCell()
		zoner.SetStyle(stylee)

		fprot := row.AddCell()
		fprot.SetStyle(stylee)

		windowsDefender := row.AddCell()
		windowsDefender.SetStyle(stylee)

		escan := row.AddCell()
		escan.SetStyle(stylee)

		mcafee := row.AddCell()
		mcafee.SetStyle(stylee)

		clameav := row.AddCell()
		clameav.SetStyle(stylee)

		fmt.Println(tdif)
		avira := row.AddCell()
		avira.SetStyle(stylee)

		for _, r := range resp.Response {

			if r.Plugin == "drweb" {
				avg.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					avgc += 1
				}
				if checlError(r.Error) != "0" {
					avge += 1

				}
			}

			if r.Plugin == "comodo" {
				zoner.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					zonerc += 1
				}
				if checlError(r.Error) != "0" {
					zonere += 1

				}
			}

			if r.Plugin == "fprot" {
				fprot.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					fprotc += 1
				}
				if checlError(r.Error) != "0" {
					fprote += 1

				}
			}

			if r.Plugin == "windows-defender" {
				windowsDefender.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					windowsDefenderc += 1
				}
				if checlError(r.Error) != "0" {
					windowsDefendere += 1

				}
			}

			if r.Plugin == "escan" {
				escan.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					escanc += 1
				}
				if checlError(r.Error) != "0" {
					escane += 1

				}
			}

			if r.Plugin == "fsecure" || r.Plugin == "fsecur" || r.Plugin == "fsecuree" {
				mcafee.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					mcafeec += 1
				}

				if checlError(r.Error) != "0" {
					mcafeee += 1

				}
			}

			if r.Plugin == "clamav" {
				clameav.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					clamavc += 1
				}
				if checlError(r.Error) != "0" {
					clamave += 1

				}
			}

			if r.Plugin == "avira" {
				avira.SetValue(check(r.Infected) + "/" + r.Error)
				if check(r.Infected) == "1" {
					avirac += 1
				}
				if checlError(r.Error) != "0" {
					avirae += 1

				}
			}

		}

		file.Close()

		fmt.Println(i+1, " of ", len(files), " is done!")
	}

	cell = row2.AddCell()
	cell = row2.AddCell()
	cell.SetStyle(styl)

	if totalSize > 1000000 {
		cell.SetValue(fmt.Sprintf("%.2fMB", (totalSize)/float64((1000000*totalCount))))

	} else {
		cell.SetValue(fmt.Sprintf("%.2fKB", (totalSize)/float64((1000*totalCount))))

	}

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(math.Round(totalResponseTime / float64(totalCount)))

	cell = row2.AddCell()

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(avgc, "/", avge))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(zonerc, "/", zonere))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(fprotc, "/", fprote))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(windowsDefenderc, "/", windowsDefendere))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(escanc, "/", escane))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(mcafeec, "/", mcafeee))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(clamavc, "/", clamave))

	cell = row2.AddCell()
	cell.SetStyle(styl)

	cell.SetValue(fmt.Sprint(avirac, "/", avirae))

	buf, err := os.Create(filename)
	if err != nil {
		panic("error create file : " + err.Error())
	}

	if err := exclFile.Write(buf); err != nil {
		panic("error write excel: " + err.Error())
	}

}

func check(infected bool) string {
	if infected {
		return "1"
	}

	return "0"
}

func checlError(err string) string {
	if err != "" {
		return "1"
	}

	return "0"
}
