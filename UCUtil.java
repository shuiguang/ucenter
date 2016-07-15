import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Date;

/**
 * Licensed under The MIT License
 * For full copyright and license information, please see the MIT-LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 * UCUtil加密解密核心类
 * @author shuiguang
 * @link https://github.com/shuiguang/ucenter
 * @license http://www.opensource.org/licenses/mit-license.php MIT License
 */
public class UCUtil {

    private static final String base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    /**
     * 加密算法
     * @param str 待加密内容
     * @param operation 加密动作
     * @param key 密钥
     * @param expiry 有效时间，单位s
     * @return 加密后的字符串
     * @throws UnsupportedEncodingException 
     */
    public static String ucAuthcode(String str, String operation, String key, int expiry) throws UnsupportedEncodingException {
        int ckey_length = 4;
        String defaultCharset = "UTF-8";
        
        key = md5(key, defaultCharset);
        
        // 密匙a会参与加解密
        String keya = md5(key.substring(0, 16), defaultCharset);
        // 密匙b会用来做数据完整性验证
        String keyb = md5(key.substring(16, 32), defaultCharset);
        
        String keyc;
        
        // 密匙c用于变化生成密文
        keyc = "";
        if(ckey_length > 0) {
            if("DECODE".equals(operation)) {
                keyc = str.substring(0, ckey_length);
            }else{
                String md5_time = md5(microtime(), defaultCharset);
                int start = md5_time.length() - ckey_length;
                keyc = md5_time.substring(start, start+ckey_length);
            }
        }
        // 参与运算的密匙
        String cryptkey = keya + md5(keya + keyc, defaultCharset);
        
        String strbuf;
        
        if("DECODE".equals(operation)) {
            str = str.substring(ckey_length);
            strbuf = decode(str);
        }else{
            expiry = expiry > 0 ? expiry + time() : 0;
            String tmpstr = expiry + "";
            if(tmpstr.length() >= 10) {
                str = tmpstr.substring(0, 10) + md5(str + keyb, defaultCharset).substring(0, 16) + str;
            }else{
                int count = 10 - tmpstr.length();
                for (int i = 0; i < count; i++) {
                    tmpstr = "0"+tmpstr;
                }
                str = tmpstr + md5(str + keyb, defaultCharset).substring(0, 16) + str;
            }
            strbuf = str;
        }
        int[] box = new int[256];
        for (int i = 0; i < box.length; i++) {
            box[i] = i;
        }
        
        char[] rndkey = new char[256];
        for (int i = 0; i < rndkey.length; i++) {
            rndkey[i] = cryptkey.charAt(i % cryptkey.length());
        }
        
        // 用固定算法打乱密匙薄，增加随机性，好像很复杂，实际上并不会增加密文的强度
        for (int i = 0, j = 0; i < 256; i++) {
            j = (j + box[i] + rndkey[i]) % 256;
            int tmp = box[i];
            box[i] = box[j];
            box[j] = tmp;
        }
        
        // 核心加密解密部分
        String s = "";
        char[] charArray = strbuf.toCharArray();
        for (int a = 0, i = 0, j = 0; i < charArray.length; i++) {
            a = (a + 1) % 256;
            j = (j + box[a]) % 256;
            int tmp = box[a];
            box[a] = box[j];
            box[j] = tmp;
            // 从密匙薄得出密匙进行异或，再转成字符
            char c = (char) (charArray[i]^box[(box[a] + box[j]) % 256]);
            s += c + "";
        }
        if("DECODE".equals(operation)) {
            int prefix;
            // 与js差异之一
            try{
                prefix = Integer.parseInt(s.substring(0, 10));
            }catch(Exception e) {
                prefix = 0;
            }
            if(("0000000000".equals(s.substring(0, 10)) || prefix - time() > 0) && md5(s.substring(26) + keyb, defaultCharset).substring(0, 16).equals(s.substring(10, 26))) {
                s = s.substring(26);
            }else{
                s = "";
            }
        }else{
            s = encode(s);
            s = s.replaceAll("=", "");
            s = keyc + s;
        }
        return s;
    }
    
    /**
     * md5 加密 
     * @author Z
     * @param s
     * @param charset
     * @return String 加密后的32位长度的字符串
     */
    private final static String md5(String s, String charset) {
        try {
            byte[] btInput = s.getBytes(charset);
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            mdInst.update(btInput);
            byte[] md = mdInst.digest();
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < md.length; i++) {
                int val = ((int) md[i]) & 0xff;
                if (val < 16){
                    sb.append("0");
                }
                sb.append(Integer.toHexString(val));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * 返回当前微秒数
     * @return
     */
    private static String microtime() {
        long unixtime_ms = new Date().getTime();
        int sec = (int) unixtime_ms / 1000;
        return (unixtime_ms - (sec * 1000)) / 1000 + " " + sec;
    }
    
    /**
     * 获取当前Unix时间秒数
     * @return
     */
    private static int time() {
        long time = new Date().getTime()/1000;
        return (int) time;
    }
    
    /**
     * base64编码(纯英文)
     * @param str
     * @return
     */
    private static String encode(String str) {
        String out = "";
        int i = 0;
        int len = 0;
        int c1, c2, c3;
        len = str.length(); 
        while(i < len) {
            c1 = (int) str.charAt(i++) & 0xff; 
            if(i == len) 
            { 
                out += base64EncodeChars.charAt(c1 >> 2); 
                out += base64EncodeChars.charAt((c1 & 0x3) << 4); 
                out += "=="; 
                break; 
            } 
            c2 = (int) str.charAt(i++); 
            if(i == len) 
            {
                out += base64EncodeChars.charAt(c1 >> 2); 
                out += base64EncodeChars.charAt(((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)); 
                out += base64EncodeChars.charAt((c2 & 0xF) << 2); 
                out += "="; 
                break; 
            } 
            c3 = (int) str.charAt(i++); 
            out += base64EncodeChars.charAt(c1 >> 2); 
            out += base64EncodeChars.charAt(((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)); 
            out += base64EncodeChars.charAt(((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)); 
            out += base64EncodeChars.charAt(c3 & 0x3F); 
        }
        
        return out;
    }

    /**
     * base64解码(纯英文)
     * @param str
     * @return
     */
    private static String decode(String str) {
        int[] base64DecodeChars = new int[]{ 
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, 
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, 
                -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1}; 
        int c1, c2, c3, c4;
        int i = 0;
        int len = 0;
        String out = "";
        len = str.length();
        while(i < len) { 
        /* c1 */ 
        do { 
            c1 = base64DecodeChars[(int) str.charAt(i++) & 0xff]; 
        } while(i < len && c1 == -1); 
        if(c1 == -1) 
            break; 

        /* c2 */ 
        do { 
            c2 = base64DecodeChars[(int) str.charAt(i++) & 0xff]; 
        } while(i < len && c2 == -1); 
        if(c2 == -1) 
            break; 
        out += (char) ((c1 << 2) | ((c2 & 0x30) >> 4)) + ""; 

        /* c3 */ 
        do { 
            c3 = ((int) str.charAt(i++) & 0xff); 
            if(c3 == 61) 
            return out; 
            c3 = base64DecodeChars[c3]; 
        } while(i < len && c3 == -1); 
        if(c3 == -1) 
            break; 
        out += (char) (((c2 & 0XF) << 4) | ((c3 & 0x3C) >> 2)) + ""; 

        /* c4 */ 
        do {
            // 与js差异之二
            try{
                c4 = (int) str.charAt(i++) & 0xff;
                if(c4 == 61) 
                return out; 
                c4 = base64DecodeChars[c4]; 
            } catch (Exception e) {
                c4 = -1;
            }
        } while(i < len && c4 == -1); 
        if(c4 == -1) 
            break; 
        out += (char) (((c3 & 0x03) << 6) | c4) + ""; 
        } 
        return out;
    }
    
    public static String ucAuthcode(String str, String operation, String key) throws UnsupportedEncodingException {
        return ucAuthcode(str, operation, key, 0);
    }

    public static String ucAuthcode(String str, String operation) throws UnsupportedEncodingException {
        return ucAuthcode(str, operation, "", 0);
    }
}
