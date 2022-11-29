package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg/eth"
	"testing"
)

func FuzzPointEvaluation(f *testing.F) {
	f.Add(common.FromHex("013c03613f6fc558fb7e61e75602241ed9a2f04e36d8670aadd286e71b5ca9cc420000000000000000000000000000000000000000000000000000000000000031e5a2356cbc2ef6a733eae8d54bf48719ae3d990017ca787c419c7d369f8e3c83fac17c3f237fc51f90e2c660eb202a438bc2025baded5cd193c1a018c5885bc9281ba704d5566082e851235c7be763b2a99adff965e0a121ee972ebc472d02944a74f5c6243e14052e105124b70bf65faf85ad3a494325e269fad097842cba"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 192 {
			return
		}
		if len(data) > 512 {
			return
		}
		data = data[:192]
		eth.PointEvaluationPrecompile(data[:192])

		// Do a second call, where we calculate the versioned hash.

		// Data layout:
		// 0-32    Versioned Hash <-- We calculate this
		// 32-64   x
		// 64-96   y
		// 96-144: kzg point
		// 144-192 Quotient kzg

		var dataKZG [48]byte
		copy(dataKZG[:], data[96:144])
		vHash := eth.KZGToVersionedHash(eth.KZGCommitment(dataKZG))
		copy(data[0:32], vHash[:])
		eth.PointEvaluationPrecompile(data[:192])
	})
}

/*
func TestGenCorpus(t *testing.T) {
	file, _ := os.Open("corpus2")
	fscanner := bufio.NewScanner(file)
	var cases []*precompiledTest
	i := 0
	for fscanner.Scan() {
		data := common.FromHex(fscanner.Text())
		if len(data) > 192 {
			data = data[:192]
		}
		res, err := eth.PointEvaluationPrecompile(data)
		p := &precompiledTest{
			Input:       hexutil.Encode(data),
			Gas:         50000,
			Name:        fmt.Sprintf("fuzzcorp-%d", i),
			NoBenchmark: false,
		}
		if err != nil {
			p.ExpectedError = err.Error()
		} else {
			p.Expected = hexutil.Encode(res)
		}

		if len(data) < 192 {
			i++
			continue
		}
		cases = append(cases, p)
		var dataKZG [48]byte
		copy(dataKZG[:], data[96:144])
		vHash := eth.KZGToVersionedHash(eth.KZGCommitment(dataKZG))
		copy(data[0:32], vHash[:])
		if p.Input == hexutil.Encode(data) {
			i++
			continue
		}

		res, err = eth.PointEvaluationPrecompile(data[:192])
		p = &precompiledTest{
			Input:       hexutil.Encode(data),
			Expected:    hexutil.Encode(res),
			Gas:         50000,
			Name:        fmt.Sprintf("fuzzcorp-%d-b", i),
			NoBenchmark: false,
		}
		if err != nil {
			p.ExpectedError = err.Error()
		} else {
			p.Expected = hexutil.Encode(res)
		}
		cases = append(cases, p)
		i++
	}
	out, _ := json.MarshalIndent(cases, "", "  ")
	fmt.Println(string(out))

}
*/
