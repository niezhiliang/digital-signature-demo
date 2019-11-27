package cc.huluwa.tianwei.sign.demo.utils;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.Image;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

/**
 * @Author NieZhiLiang
 * @Email nzlsgg@163.com
 * @GitHub https://github.com/niezhiliang
 * @Date 2019/11/26 5:22 下午
 */
public class ImageUtils {

    /**
     * 切割图片
     *
     * @param imgPath 原始图片路径
     * @param n       切割份数
     * @return itextPdf的Image[]
     * @throws IOException
     * @throws BadElementException
     */
    public static Image[] subImages(String imgPath, int n) throws IOException, BadElementException {
        Image[] nImage = new Image[n];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BufferedImage img = ImageIO.read(new File(imgPath));
        int h = img.getHeight();
        int w = img.getWidth();

        int sw = w / n;
        for (int i = 0; i < n; i++) {
            BufferedImage subImg;
            //最后剩余部分
            if (i == n - 1) {
                subImg = img.getSubimage(i * sw, 0, w - i * sw, h);
                //前n-1块均匀切
            } else {
                subImg = img.getSubimage(i * sw, 0, sw, h);
            }

            ImageIO.write(subImg, imgPath.substring(imgPath.lastIndexOf('.') + 1), out);
            nImage[i] = Image.getInstance(out.toByteArray());
            out.flush();
            out.reset();
        }
        return nImage;
    }
}
