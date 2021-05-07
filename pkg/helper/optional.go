package helper

// IfElse simple if else
func IfElse(condition bool, ifVal interface{}, elVal interface{}) interface{} {
	if condition {
		return ifVal
	}
	return elVal
}
