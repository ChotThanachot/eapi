package main

import (
	"os"

	"github.com/pricklycleane/eapi"
	"github.com/pricklycleane/eapi/plugins/echo"
	"github.com/pricklycleane/eapi/plugins/gin"
)

func main() {
	eapi.NewEntrypoint(
		gin.NewPlugin(),
		echo.NewPlugin(),
	).Run(os.Args)
}
