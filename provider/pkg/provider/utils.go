package provider

// import (
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// 	"fmt"
// )

// func appendTags(argsTags pulumi.StringMapInput, additionalTags pulumi.StringMap) pulumi.StringMapInput {
//     return pulumi.All(argsTags, additionalTags).ApplyT(func(all []interface{}) pulumi.StringMap {
//         combinedTags := pulumi.StringMap{}

//         // Unpack and add the original tags
//         if originalTags, ok := all[0].(map[string]string); ok {
//             for k, v := range originalTags {
//                 combinedTags[k] = pulumi.String(v)
//             }
//         } else {
//             fmt.Println("Warning: original tags are not a map[string]string")
//         }

//         // Unpack and add/overwrite with the additional tags
//         if addTags, ok := all[1].(map[string]string); ok {
//             for k, v := range addTags {
//                 combinedTags[k] = pulumi.String(v)
//             }
//         } else {
//             fmt.Println("Warning: additional tags are not a map[string]string")
//         }

//         return combinedTags
//     }).(pulumi.StringMapInput)
// }
