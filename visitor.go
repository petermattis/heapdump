// +build ignore

package main

import (
	"fmt"
	"go/ast"
	"log"
	"os"

	"code.google.com/p/go.tools/go/loader"
)

type visitor struct {
	prog *loader.Program
	pkg  *loader.PackageInfo
}

func (v *visitor) Visit(node ast.Node) ast.Visitor {
	if i, ok := node.(*ast.Ident); ok {
		if o, ok := v.pkg.Defs[i]; ok && o != nil {
			fmt.Printf("%d %s: %s %s\n", node.Pos(), v.prog.Fset.Position(node.Pos()),
				o.Id(), o.Type())
		}
	}
	// else if e, ok := node.(ast.Expr); ok {
	// 	if t, ok := v.pkg.Types[e]; ok {
	// 		fmt.Printf("%d %s: %s\n", node.Pos(), v.prog.Fset.Position(node.Pos()), t.Type)
	// 		if _, ok := node.(*ast.StarExpr); ok {
	// 			return nil
	// 		}
	// 	}
	// 	return v
	// }
	return v
}

func main() {
	var conf loader.Config
	// conf.ParserMode = parser.ParseComments

	_, err := conf.FromArgs(os.Args[1:], false)
	if err != nil {
		log.Fatal(err)
	}
	prog, err := conf.Load()
	if err != nil {
		log.Fatal(err)
	}

	for _, pkg := range prog.Created {
		fmt.Printf("%s\n", pkg.Pkg)
		// for t, v := range pkg.Types {
		// 	printer.Fprint(os.Stdout, prog.Fset, t)
		// 	fmt.Printf(" %s\n", v)
		// }
		// for i, o := range pkg.Defs {
		// 	printer.Fprint(os.Stdout, prog.Fset, i)
		// 	fmt.Printf(" %s\n", o)
		// }
		for _, file := range pkg.Files {
			ast.Walk(&visitor{prog, pkg}, file)
			// printer.Fprint(os.Stdout, prog.Fset, file)
		}
	}
}
