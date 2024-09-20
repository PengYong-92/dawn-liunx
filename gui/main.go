package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	// 创建应用程序实例
	myApp := app.New()
	myWindow := myApp.NewWindow("Hello")

	// 设置窗口内容
	myWindow.SetContent(container.NewVBox(
		widget.NewLabel("Hello, World!"),
		widget.NewButton("Quit", func() {
			myApp.Quit()
		}),
	))

	// 设置窗口尺寸并显示
	myWindow.Resize(fyne.NewSize(200, 100))
	myWindow.ShowAndRun()
}
