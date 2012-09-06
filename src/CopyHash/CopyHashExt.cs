namespace CopyHash
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Windows.Forms;

    using KeePass.Plugins;

    using KeePassLib;

    public class CopyHashExt : Plugin
    {
        private IPluginHost host;

        private ToolStripSeparator separator;

        private ToolStripMenuItem copySHA256;

        public override bool Initialize(IPluginHost host)
        {
            this.host = host;

            var contextMenu = host.MainWindow.EntryContextMenu;

            this.separator = new ToolStripSeparator();
            contextMenu.Items.Add(this.separator);
            this.copySHA256 = new ToolStripMenuItem();
            this.copySHA256.Text = "Copy SHA256 hashed password";
            this.copySHA256.Click += this.OnCopySha256;
            contextMenu.Items.Add(this.copySHA256);

            return true;
        }

        public override void Terminate()
        {
            var contextMenu = host.MainWindow.EntryContextMenu;

            contextMenu.Items.Remove(this.separator);
            contextMenu.Items.Remove(this.copySHA256);
        }

        private void OnCopySha256(object sender, EventArgs e)
        {
            PwEntry[] pwes = this.host.MainWindow.GetSelectedEntries();

            if (pwes == null || pwes.Length != 1)
            {
                MessageBox.Show("Please select a single entry", "Copy Hash Plugin");
                return;
            }

            var entry = KeePassLib.Collections.PwObjectList<PwEntry>.FromArray(pwes).First();

            if (!entry.Strings.Any(ps => string.Equals(ps.Key, "password", StringComparison.InvariantCultureIgnoreCase)))
            {
                MessageBox.Show("Cannot find password", "Copy Hash Plugin");
               return;
            }

            var passwordProtectedString =
                entry.Strings.First(ps => string.Equals(ps.Key, "password", StringComparison.InvariantCultureIgnoreCase)).Value;

            var hasher = SHA256.Create();
            var hash = ByteArrayToString(hasher.ComputeHash(passwordProtectedString.ReadUtf8()));

            Clipboard.SetText(hash);
        }

        private static string ByteArrayToString(byte[] input)
        {
            var hex = BitConverter.ToString(input);
            return hex.Replace("-", "");
        }
    }
}