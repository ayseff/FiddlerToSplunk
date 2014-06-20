using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Threading.Tasks;
using Fiddler;
using ServiceStack.Text;
using Splunk.Client;

namespace FiddlerToSplunk
{
    class Program
    {
        const string IndexName = "fiddler-index";
        static bool _quitRequested;
        static Service _service;
        static Index _index;
        static TransmitterArgs _args;
        static Transmitter _transmitter;

        static void Main()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;

            FiddlerApplication.SetAppDisplayName("FiddlerToSplunk");
            FiddlerApplication.OnNotification += OnNotification;
            FiddlerApplication.Log.OnLogString += OnLogString;
            FiddlerApplication.AfterSessionComplete += SessionComplete;

            _service = new Service(Scheme.Https, "localhost", 8089, new Namespace(user: "nobody", app: "search"));

            _args = new TransmitterArgs { Host = "localhost", Source = "FiddlerToSplunk", SourceType = "JSON" };

            SplunkSetup("admin", "changeme").Wait();

            FiddlerApplication.Startup(8877, true, false, true);

            MainFeedbackLoop();

            FiddlerApplication.Shutdown();
        }

        static async Task SplunkSetup(string username, string password)
        {
            await _service.LoginAsync(username, password);
            _index = await _service.Indexes.GetOrNullAsync(IndexName);
            if (_index != null)
            {
                await _index.RemoveAsync();
            }
            _index = await _service.Indexes.CreateAsync(IndexName);
            await _index.EnableAsync();
            _transmitter = _service.Transmitter;
        }

        static async Task SendToSplunk(string data)
        {
            Console.Write(".");
            await _transmitter.SendAsync(data, IndexName, _args);
        }

        static void SessionComplete(Session s)
        {
            if (s.hostname.Equals("localhost", StringComparison.InvariantCultureIgnoreCase) || 
                s.hostname.Equals(Environment.MachineName, StringComparison.InvariantCultureIgnoreCase))
                return;

            var strippedDownSession = new
            {
                s.bHasResponse,
                s.bHasWebSocketMessages,
                s.bypassGateway,
                s.clientIP,
                s.clientPort,
                s.fullUrl,
                s.host,
                s.hostname,
                s.id,
                s.isFTP,
                s.isHTTPS,
                s.isTunnel,
                s.LocalProcessID,
                s.PathAndQuery,
                s.port,
                s.RequestMethod,
                s.responseCode,
                s.SuggestedFilename,
                s.Tag,
                s.TunnelEgressByteCount,
                s.TunnelIngressByteCount,
                s.TunnelIsOpen,
                s.url,
                RequestHeaders = s.oRequest.headers.ToDictionary(),
                ResponseHeaders = s.oResponse.headers.ToDictionary()
            };
            var data = JsonSerializer.SerializeToString(strippedDownSession);
            SendToSplunk(data).Wait();
        }

        static void MainFeedbackLoop()
        {
            Console.WriteLine("Application running, press q to quit");
            while (!_quitRequested)
            {
                try
                {
                    var keyValue = Console.ReadKey(true).KeyChar.ToString(CultureInfo.InvariantCulture).ToLower();

                    if (keyValue == "q")
                    {
                        _quitRequested = true;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e);
                }
            }
        }

        static void OnLogString(object sender, LogEventArgs logEventArgs)
        {
            Console.WriteLine("LogOnOnLogString: {0}", logEventArgs.LogString);
        }

        static void OnNotification(object sender, NotificationEventArgs e)
        {
            Console.WriteLine("OnNotification: {0}", e.NotifyString);
        }
    }

    public static class FiddlerExtensions
    {
        public static Dictionary<string, string> ToDictionary(this HTTPHeaders headers)
        {
            if (headers == null) return null;

            var result = new Dictionary<string, string>();

            foreach (var item in headers.ToArray())
            {
                if (!result.ContainsKey(item.Name))
                    result.Add(item.Name, item.Value);
                else
                    result[item.Name] += ";" + item.Value;
            }

            return result;
        }
    }
}
