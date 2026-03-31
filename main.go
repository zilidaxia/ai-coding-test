package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"ai-coding-test/internal/config"
	"ai-coding-test/internal/output"
	"ai-coding-test/internal/scanner"
)

func main() {
	cfg, err := config.ParseCLI(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	assets, err := scanner.Run(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}

	writer, closeWriter, err := resolveWriter(cfg.OutputPath)
	if err != nil {
		log.Fatal(err)
	}
	if closeWriter != nil {
		defer closeWriter()
	}

	if err := output.WriteJSONL(writer, assets); err != nil {
		log.Fatal(err)
	}

	if cfg.OutputPath != "" {
		_, _ = fmt.Fprintf(os.Stderr, "结果已写入 %s\n", cfg.OutputPath)
	}
}

// resolveWriter 负责把输出目标统一为 io.Writer，便于同时支持 stdout 和文件。
func resolveWriter(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, nil, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return file, file.Close, nil
}
