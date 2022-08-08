package lvhrunner

// type RunTestsResults struct {
// 	NrTests, NrFailedTests int
// }

// func RunTests(
// 	rcnf *RunConf, qemuBin string, qemuArgs []string,
// ) (*RunTestsResults, error) {
// 	fmt.Printf("results directory: %s\n", rcnf.TesterConf.ResultsDir)
// 	resFile := filepath.Join(rcnf.TesterConf.ResultsDir, "results.json")

// 	f, err := os.Open(resFile)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to open results file %s: %v", resFile, err)
// 	}
// 	defer f.Close()

// 	var results []vmtests.Result
// 	decoder := json.NewDecoder(f)
// 	for {
// 		var result vmtests.Result
// 		if err := decoder.Decode(&result); err == io.EOF {
// 			break
// 		} else if err != nil {
// 			return nil, fmt.Errorf("JSON decoding failed: %w", err)
// 		}

// 		results = append(results, result)
// 	}

// 	var totalDuration time.Duration
// 	errCnt := 0
// 	w := new(tabwriter.Writer)
// 	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
// 	for _, r := range results {
// 		totalDuration += r.Duration
// 		ok := "✅"
// 		if r.Error {
// 			ok = "❌"
// 			errCnt++
// 		}
// 		fmt.Fprintf(w, "%s\t%s\t%s\t(%s)\n", ok, r.Name, r.Duration.Round(time.Millisecond), totalDuration.Round(time.Millisecond))
// 	}
// 	w.Flush()

// 	return &RunTestsResults{
// 		NrTests:       len(results),
// 		NrFailedTests: errCnt,
// 	}, nil
// }
