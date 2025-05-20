package banner

import (
	"fmt"
	"github.com/fatih/color"
)

func ShowBanner() {
	bannerColor := color.New(color.FgRed, color.Bold)
	authorColor := color.New(color.FgCyan)
	
	banner := `
    _   __      _____ ____    __    _ 
   / | / /___  / ___// __ \  / /   (_)
  /  |/ / __ \ \__ \/ / / / / /   / / 
 / /|  / /_/ /___/ / /_/ / / /___/ /  
/_/ |_/\____//____/\___\_\/_____/_/   
                                      `

	bannerColor.Println(banner)
	fmt.Println()
	authorColor.Println("       🔥 NoSQL Injection Scanner v1.0")
	authorColor.Println("          Author: det0x (@det0x)")
	fmt.Println("==========================================")
	fmt.Println()
