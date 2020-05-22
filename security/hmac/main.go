// HMAC
//
//   通过哈希算法，我们可以验证一段数据是否有效，方法就是对比该数据的哈希值，例如，判断用户口令是否正确，我们用保存在数据库中的password_md5
// 对比计算md5(password)的结果，如果一致，用户输入的口令就是正确的。
//   为了防止黑客通过彩虹表根据哈希值反推原始口令，在计算哈希的时候，不能仅针对原始输入计算，需要增加一个salt来使得相同的输入也能得到不同的哈希，
// 这样，大大增加了黑客破解的难度。
//   如果salt是我们自己随机生成的，通常我们计算MD5时采用md5(message + salt)。但实际上，把salt看做一个“口令”，加salt的哈希就是：计算一段
// message的哈希时，根据不通口令计算出不同的哈希。要验证哈希值，必须同时提供正确的口令。
//   这实际上就是Hmac算法：Keyed-Hashing for Message Authentication。它通过一个标准算法，在计算哈希的过程中，把key混入计算过程中。
// 和我们自定义的加salt算法不同，Hmac算法针对所有哈希算法都通用，无论是MD5还是SHA-1。采用Hmac替代我们自己的salt算法，可以使程序算法更标准化，也更安全。
//
// HMAC算法的定义用公式表示如下：
//   HMAC（K，M）=H（（K’⊕opad）∣H（（K’⊕ipad）∣M））
//
//HMAC算法的伪码实现
//  function hmac (key, message) {
//    if (length(key) > blocksize) {
//      key = hash(key) // keys longer than blocksize are shortened
//    }
//    if (length(key) < blocksize) {
//      //keys shorter than blocksize are zero-padded (where ∥ is concatenation)
//     key = key ∥ [ 0x00 * (blocksize - length(key))] // Where * is repetition.
//    }
//    o_pad = [ 0x5c * blocksize] // Where blocksize is that of the underlying hash function
//    i_pad = [ 0x36 * blocksize]
//    o_key_pad = o_pad ⊕ key // Where ⊕ is exclusive or (XOR)
//    i_key_pad = i_pad ⊕ key
//    return hash(o_key_pad ∥ hash(i_key_pad ∥ message)) // Where ∥ is concatenation
//  }
//

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	key := "my_key"
	message := "my_message"
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(message))
	fmt.Printf("HMAC: %s", hex.EncodeToString(h.Sum(nil)))
}