using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace authenticator
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public string Identity
        {
            get { return (string)GetValue(IdentityProperty); }
            set { SetValue(IdentityProperty, value); }
        }

        //public byte[] Secret
        //{
        //    get { return (byte[])GetValue(SecretProperty); }
        //    set { SetValue(SecretProperty, value); }
        //}

        public string Secret
        {
            get { return (string)GetValue(SecretProperty); }
            set { SetValue(SecretProperty, value); }
        }

        public string QRCodeUrl
        {
            get { return (string)GetValue(QRCodeUrlProperty); }
            set { SetValue(QRCodeUrlProperty, value); }
        }

        public long Timestamp
        {
            get { return (long)GetValue(TimestampProperty); }
            set { SetValue(TimestampProperty, value); }
        }

        public int OneTimePassword
        {
            get { return (int)GetValue(OneTimePasswordProperty); }
            set { SetValue(OneTimePasswordProperty, value); }
        }

        public int SecondsToGo
        {
            get { return (int)GetValue(SecondsToGoProperty); }
            set {
                SetValue(SecondsToGoProperty, value);
                if (SecondsToGo == 30)
                    CalculateOneTimePassword();
            }
        }

        public byte[] Hmac;
        //{
        //    get { return (byte[])GetValue(HmacPart1Property); }
        //    set { SetValue(HmacPart1Property, value); }
        //}


        //private byte[] _hmac;
        //public byte[] Hmac
        //{
        //    get { return _hmac; }
        //    private set { _hmac = value; OnPropertyChanged("Hmac"); OnPropertyChanged("HmacPart1"); OnPropertyChanged("HmacPart2"); OnPropertyChanged("HmacPart3"); }
        //}


        public static readonly DependencyProperty IdentityProperty = DependencyProperty.Register("Identity", typeof(string), typeof(MainWindow), new PropertyMetadata("default value"));
        public static readonly DependencyProperty SecretProperty = DependencyProperty.Register("Secret", typeof(string), typeof(MainWindow), new PropertyMetadata("default value"));

        public static readonly DependencyProperty TimestampProperty = DependencyProperty.Register("Timestamp", typeof(long), typeof(MainWindow));
        public static readonly DependencyProperty QRCodeUrlProperty = DependencyProperty.Register("QRCodeUrl", typeof(string), typeof(MainWindow));
        public static readonly DependencyProperty OneTimePasswordProperty = DependencyProperty.Register("OneTimePassword", typeof(int), typeof(MainWindow));
        public static readonly DependencyProperty SecondsToGoProperty = DependencyProperty.Register("SecondsToGo", typeof(int), typeof(MainWindow));
     //   public static readonly DependencyProperty HmacPart1Property = DependencyProperty.Register("HmacPart1", typeof(string), typeof(MainWindow));

        private byte[] secret;

        public MainWindow()
        {
            InitializeComponent();
 
            DataContext = this;


            var timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromMilliseconds(500);
            timer.Tick += (s, e) => SecondsToGo = 30 - Convert.ToInt32(DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30);
            timer.IsEnabled = true;

            secret = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF };
            Secret = Base32.Encode(secret);
            Identity = "user@host.com";

            QRCodeUrl = GetQRCodeUrl();

       
        }

        private void CalculateOneTimePassword()
        {
            // Get the number of seconds since 1/1/1970 and devide them by 30 seconds.
            // Thus one Timestamp unit is 30 seconds.
            Timestamp = Convert.ToInt64(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);

            // Convert the 64 bit integer Timestamp to a byte array (8 bytes).
            // eg. ba d9 c7 02 00 00 00 00
            // Then reverse them (=> 00 00 00 00 02 c7 d9 ba) and write the result to the byte array "data".
            var data = BitConverter.GetBytes(Timestamp).Reverse().ToArray();

            // Generate the Hmac key from your password (byte array) and time (byte array).
            Hmac = new HMACSHA1(secret).ComputeHash(data);

            // Bit-operation: Get the last 4 bits of the Hmac. The results are always equal to or between 0 and 15.
            // The offset determines the area of the Hmac that is used to generate the time based password.
            int Offset = Hmac.Last() & 0x0F;

            //// The Hmac is 20 bytes long. A block of 4 bytes is used for the OneTimePassword, which changes each 30 seconds.
            //// 15 is the highest Offset. Therefore the last used byte is number 18 (first byte is zero based).
            //// The 19th (=last) byte is the Offset. More precisely the <a href="http://en.wikipedia.org/wiki/Nibble" title="Wiki Nibble Byte" target="_blank">right nibble</a> of the 19th byte is the Offset value.
            //// Bit masks are applied on the selected Hmac block to limit the number. The resulting bits are rotated to the left and added together.
            //// Basically we are looking at a manual "bit to integer" conversion.
            //// the result is then devided by 1,000,000 and only the remainder is taken. Consequently all results are less than 1,000,000.
            //// (The bit mask 0xff is useless. I guess it was used to emphasize the technique for readability purposes. 0x7f does make sense.)
            OneTimePassword = (
                   ((Hmac[Offset + 0] & 0x7f) << 24) |
                   ((Hmac[Offset + 1] & 0xff) << 16) |
                   ((Hmac[Offset + 2] & 0xff) << 8) |
                   (Hmac[Offset + 3] & 0xff)) % 1000000;
        }

        private string GetQRCodeUrl()
        {
            // https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
            var base32Secret = Base32.Encode(secret);
            return String.Format("https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/{0}%3Fsecret%3D{1}", Identity, base32Secret);
        }

    }
}



