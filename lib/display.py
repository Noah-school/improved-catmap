from lib.simulate_eink import SimulatedEPD
from PIL import ImageDraw, ImageFont, Image
import logging

logging.basicConfig(filename='./output/errors.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class ImageDisplay:
    def __init__(self):
        self.width = 122
        self.height = 250
        
    def getbuffer(self, image):
        return image

    def display(self, image):
        # print("Full refresh triggered.")
        self._simulate_display(image)

    def _simulate_display(self, image):
        image = Image.frombytes('1', (self.width, self.height), image)
        image.save("./output/epd_image.png")
        # print("Image saved as epd_image.png")



def initialize_display(emulate=False):
    try:
        if emulate:
            return SimulatedEPD()
        else:
            from lib.waveshare_epd import epd2in13_V4
            epd = epd2in13_V4.EPD()
            epd.init()
            return epd
    except Exception as e:
        logging.error(f"Error initializing display: {e}")
        raise

def update_display(epd, image, text_styles, full_refresh=False, logo_path=None):
    try:
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, epd.width, epd.height), fill=0)
        
        if logo_path:
            logo = Image.open(logo_path)
            logo_width, logo_height = logo.size
            if logo_width > epd.width or logo_height > epd.height:
                logo.thumbnail((epd.width, epd.height))
            center_x = (epd.width - logo.width) // 2
            center_y = (epd.height - logo.height) // 2
            image.paste(logo, (center_x, center_y))
        
        for style in text_styles:
            text = style['text']
            position = style['position']
            font_size = style['font_size']
            try:
                if epd.width == 122 and epd.height == 250:
                    font = ImageFont.load_default()
                else:
                    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
            except IOError:
                logging.error("Error loading font:  using default font")
                font = ImageFont.load_default()

            draw.text(position, text, font=font, fill=255)

        epd.displayPartial(epd.getbuffer(image))
        if full_refresh:
            epd.display(epd.getbuffer(image))
        else:
            epd.displayPartial(epd.getbuffer(image))
        
        epdImg = ImageDisplay()
        epdImg.display(epd.getbuffer(image).tobytes())
        
    except Exception as e:
        logging.error(f"Error updating display: {e}")