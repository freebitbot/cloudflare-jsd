package deobf

import (
	"os"

	"github.com/t14raptor/go-fast/generator"
	"github.com/t14raptor/go-fast/parser"
	"github.com/t14raptor/go-fast/transform/simplifier"
	"github.com/xkiian/cloudflare-jsd/visitors/extract"
)

func DeobfuscateAndExtract(src *string) (*extract.Ctx, error) {
	ast, err := parser.ParseFile(*src)
	if err != nil {
		return nil, err
	}

	UnrollMaps(ast)
	SequenceUnroller(ast)
	callee := ReplaceReassignments(ast)
	ReplaceStrings(ast, callee)
	ConcatStrings(ast)
	simplifier.Simplify(ast, false)

	os.WriteFile("out.js", []byte(generator.Generate(ast)), 0644)

	return extract.ParseScript(ast), nil
}
