import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Licensed under The MIT License
 * For full copyright and license information, please see the MIT-LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 * UCUtil测试类
 * @author shuiguang
 * @link https://github.com/shuiguang/ucenter
 * @license http://www.opensource.org/licenses/mit-license.php MIT License
 */
public class UCUtilTest {

    public static void main(String[] args) throws InterruptedException, IOException {
        
        // 密钥
        String key = "key";
        
        // 过期时间,单位s
        int expiry = 1;
        
        // 加密消息得到密文
        String ucAuthcode = UCUtil.ucAuthcode(URLEncoder.encode("我的世界", "UTF-8"), "ENCODE", key, expiry);
        
        // 打印出密文
        System.out.println(ucAuthcode);
        
        // 本地解析得到明文
        String result2 = UCUtil.ucAuthcode(ucAuthcode, "DECODE", key, expiry);

        // 如果未超过expiry,则可以打印出明文
        System.out.println("result2="+URLDecoder.decode(result2, "UTF-8"));

        // 程序休眠expiry秒后密文自动过期
        Thread.sleep(expiry*1000);

        // 重新解析密文尝试得到明文
        String result3 = UCUtil.ucAuthcode(ucAuthcode, "DECODE", key, expiry);

        // 密文过期导致打印出空字符串
        System.out.println("result3="+URLDecoder.decode(result3, "UTF-8"));
        
    }
}
