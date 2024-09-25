package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/go-memdb"
	"github.com/ryanuber/go-glob"
)

type Alias struct {
	ID             string
	MountAccessor  string
	Name           string
	WildcardPrefix string
	WildcardSuffix string
	NamespaceID    string
}

type CustomStringFieldIndex struct {
	Field     string
	Lowercase bool
}

func (s *CustomStringFieldIndex) FromObject(obj interface{}) (bool, []byte, error) {
	v := reflect.ValueOf(obj)
	v = reflect.Indirect(v) // Dereference the pointer if any

	fv := v.FieldByName(s.Field)
	isPtr := fv.Kind() == reflect.Ptr
	fv = reflect.Indirect(fv)
	if !isPtr && !fv.IsValid() {
		return false, nil,
			fmt.Errorf("field '%s' for %#v is invalid %v ", s.Field, obj, isPtr)
	}

	if isPtr && !fv.IsValid() {
		val := ""
		return false, []byte(val), nil
	}

	val := fv.String()
	if val == "" {
		return false, nil, nil
	}

	if s.Lowercase {
		val = strings.ToLower(val)
	}

	// Prepend the null, unlike StringFieldIndex
	val = "\x00" + val
	return true, []byte(val), nil
}

func (s *CustomStringFieldIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	arg, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("argument must be a string: %#v / %T", args[0], args[0])
	}
	if s.Lowercase {
		arg = strings.ToLower(arg)
	}
	// Add the null character as a terminator
	arg = "\x00" + arg
	return []byte(arg), nil
}

// Prefix from args takes the argument as a string and prepends a null.
func (s *CustomStringFieldIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	return s.FromArgs(args...)
}

// WildcardFieldIndex is a simple custom indexer that doesn't add any suffixes to its
// object keys; this is compatible with the LongestPrefixMatch algorithm.
type WildcardFieldIndex struct {
	Field     string
	Lowercase bool
	Suffix    bool
}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (s *WildcardFieldIndex) FromObject(obj interface{}) (bool, []byte, error) {
	v := reflect.ValueOf(obj)
	v = reflect.Indirect(v) // Dereference the pointer if any

	fv := v.FieldByName(s.Field)
	isPtr := fv.Kind() == reflect.Ptr
	fv = reflect.Indirect(fv)
	if !isPtr && !fv.IsValid() {
		return false, nil,
			fmt.Errorf("field '%s' for %#v is invalid %v ", s.Field, obj, isPtr)
	}

	if isPtr && !fv.IsValid() {
		val := ""
		return false, []byte(val), nil
	}

	val := fv.String()
	if val == "" {
		return false, nil, nil
	}

	if s.Lowercase {
		val = strings.ToLower(val)
	}

	// Use an unbounded split so suffix matches can work.
	split := strings.Split(val, "*")
	if len(split) < 2 {
		return false, nil, fmt.Errorf("no wildcard (`*`) in field value; refusing to parse")
	}

	// If we want to match on the suffix, add the reverse of the portion after
	// the last glob.
	if s.Suffix {
		val = Reverse(split[len(split)-1])
	} else {
		val = split[0]
	}

	fmt.Printf("using value: %#v (len: %v) from %#v (field %v)\n", val, len(val), obj, s.Field)

	// Prepend the null, unlike StringFieldIndex
	val = "\x00" + val
	return true, []byte(val), nil
}

func (s *WildcardFieldIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	arg, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("argument must be a string: %#v / %T", args[0], args[0])
	}
	if s.Lowercase {
		arg = strings.ToLower(arg)
	}
	if s.Suffix {
		arg = Reverse(arg)
	}
	// Add the null character as a terminator
	arg = "\x00" + arg
	return []byte(arg), nil
}

// Prefix from args takes the argument as a string and prepends a null.
func (s *WildcardFieldIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	return s.FromArgs(args...)
}

func main() {
	iStoreSchema := &memdb.DBSchema{
		Tables: make(map[string]*memdb.TableSchema),
	}

	groupAliasesTable := "group_aliases"

	groupAliasesTableSchema := &memdb.TableSchema{
		Name: groupAliasesTable,
		Indexes: map[string]*memdb.IndexSchema{
			"id": {
				Name:   "id",
				Unique: true,
				Indexer: &memdb.StringFieldIndex{
					Field: "ID",
				},
			},
			"wildcard_factors": {
				Name:   "wildcard_factors",
				Unique: true,
				Indexer: &memdb.CompoundIndex{
					Indexes: []memdb.Indexer{
						&CustomStringFieldIndex{
							Field: "MountAccessor",
						},
						&CustomStringFieldIndex{
							Field: "WildcardPrefix",
						},
						&CustomStringFieldIndex{
							Field: "WildcardSuffix",
						},
					},
					AllowMissing: true,
				},
			},
			"name": {
				Name: "name",
				Indexer: &memdb.StringFieldIndex{
					Field: "Name",
				},
			},
			"namespace_id": {
				Name: "namespace_id",
				Indexer: &memdb.StringFieldIndex{
					Field: "NamespaceID",
				},
			},
		},
	}

	iStoreSchema.Tables[groupAliasesTable] = groupAliasesTableSchema

	db, err := memdb.NewMemDB(iStoreSchema)
	if err != nil {
		panic(fmt.Sprintf("failed to create db: %v", err))
	}

	token := "auth_token_240238ba"
	userpass := "auth_userpass_6abf077d"

	txn := db.Txn(true)
	data := []*Alias{
		&Alias{ID: "aid-1", MountAccessor: token, Name: "prod-*", NamespaceID: "nsid-11"},
		&Alias{ID: "aid-2", MountAccessor: token, Name: "*-20240924", NamespaceID: "nsid-12"},
		&Alias{ID: "aid-3", MountAccessor: userpass, Name: "prod-*", NamespaceID: "nsid-13"},
		&Alias{ID: "aid-4", MountAccessor: userpass, Name: "*-20240924", NamespaceID: "nsid-14"},
		&Alias{ID: "aid-5", MountAccessor: token, Name: "prod-*-20240924", NamespaceID: "nsid-15"},
	}
	for i, d := range data {
		if strings.Contains(d.Name, "*") {
			split := strings.Split(d.Name, "*")
			if len(split) < 2 {
				panic(fmt.Errorf("[%d], no wildcard (`*`) in field value; refusing to parse", i))
			}

			d.WildcardPrefix = split[0]
			d.WildcardSuffix = Reverse(split[len(split)-1])
		} else {
			panic("here")
		}

		fmt.Printf("[%d], Inserting: %#v\n", i, d)

		if err := txn.Insert("group_aliases", d); err != nil {
			panic(fmt.Sprintf("[%d] failed to insert data: %v / %v", i, d, err))
		}
	}
	txn.Commit()

	fmt.Println("ischema: ", iStoreSchema)
	fmt.Println("schema: ", db.DBSchema())
	fmt.Println("")

	fmt.Println("Performing iteration")
	func() {
		txn = db.Txn(false)
		defer txn.Abort()

		ri, err := txn.Get("group_aliases", "wildcard_factors_prefix")
		if err != nil {
			panic(fmt.Sprintf("failed to get results iterator to walk database: %v", err))
		}

		elem := ri.Next()
		for elem != nil {
			fmt.Printf(" - element: %#v\n", elem)
			elem = ri.Next()
		}
	}()
	fmt.Println("")

	queries := []string{
		"prod-20240924",
		"prod-",
		"prod-live-20240924",
		"prod-abcd",
		"dev-20240924",
	}
	for _, query := range queries {
		fmt.Println("Performing query: " + query)
		func(name string) {
			txn = db.Txn(false)
			defer txn.Abort()

			ri, err := txn.LowerBound("group_aliases", "wildcard_factors_prefix", token, name, Reverse(name))
			if err != nil {
				panic(fmt.Sprintf("failed to fetch: %v", err))
			}

			matches := 0
			elem := ri.Next()
			for elem != nil {
				a := elem.(*Alias)
				if a.MountAccessor != token {
					panic(fmt.Sprintf("bad match in result: invalid mount accessor: %#v", a))
				}
				fmt.Printf(" - element: %#v [%v]\n", elem, glob.Glob(a.Name, name))
				if glob.Glob(a.Name, name) {
					matches += 1
				}
				elem = ri.Next()
			}

			expected := 0
			for _, alias := range data {
				if glob.Glob(alias.Name, name) && alias.MountAccessor == token {
					if !strings.HasPrefix(name, alias.WildcardPrefix) {
						panic(fmt.Sprintf("bad match: %#v doesn't match prefix: %#v", name, alias))
					}
					if !strings.HasPrefix(Reverse(name), alias.WildcardSuffix) {
						panic(fmt.Sprintf("bad match: %#v doesn't match suffix: %#v", name, alias))
					}
					expected += 1
				}
			}

			if matches != expected {
				panic(fmt.Sprintf("mismatch on query: got %v vs expected %v", matches, expected))
			}
		}(query)
		fmt.Println("")
	}

	fmt.Println("db: ", db)
}
