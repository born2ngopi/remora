package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/gocolly/colly/v2"
)

func GetSeverityGHSA(id string) (string, error) {
	url := fmt.Sprintf("https://github.com/advisories/%s", id)

	c := colly.NewCollector()

	var severity string

	c.OnHTML("span.Label--orange", func(e *colly.HTMLElement) {
		severity = strings.ReplaceAll(e.Text, " severity", "")
	})

	c.OnError(func(r *colly.Response, err error) {
		log.Println("Error:", err)
	})

	err := c.Visit(url)

	return severity, err
}
