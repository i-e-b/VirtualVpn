using SkinnyJson;
using VirtualVpn.Helpers;
using VirtualVpn.Web;

namespace TestProxy;

class TestProxyApiProgram
{
    public static void Main(string[] args)
    {
        //Console.Write("KeyGen: "); // niceshortapikey
        var keyGen = "niceshortapikey";
        Console.WriteLine();

        if (string.IsNullOrEmpty(keyGen))
        {
            Console.WriteLine("Invalid KeyGen");
            return;
        }

        Console.WriteLine("Building API call");


        var timestamp = ProxyCipher.TimestampNow;
        var cipher = new ProxyCipher(keyGen, timestamp);

        var proxyRequest = new HttpProxyRequest
        {
            Url = "http://192.168.0.40/test/remote", // who we want to talk to
            ProxyLocalAddress = "55.55.55.55", // who we are pretending to be
            Headers = { { "Accept", "*/*" } },
            HttpMethod = "GET",
            Body = null
        };

        var proxyRequestBytes = cipher.Encode(Json.Freeze(proxyRequest));
        
        using var httpClient = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "http://94.130.108.249:8011/api/send");
        request.Content = new ByteArrayContent(proxyRequestBytes);

        request.Headers.Add("X-Api-Key", cipher.MakeKey()); // Hash output of timestamp + ApiKey
        request.Headers.Add("X-Api-TS", cipher.Timestamp);  // Caller's claimed local time (UTC, in ticks, base64)
        
        using var response = httpClient.Send(request);

        if (response.IsSuccessStatusCode)
        {
            Console.WriteLine($"Proxy call returned {response.StatusCode} {response.ReasonPhrase}; {response.Content.Headers.ContentLength??-1} bytes");
            try
            {
                var encrypted = Sync.Run(()=>response.Content.ReadAsByteArrayAsync());
                Console.WriteLine(Bit.Describe("encrypted", encrypted));
                
                var plain = cipher.Decode(encrypted);
                Console.WriteLine(plain);
                
                var outcome = Json.Defrost<HttpProxyResponse>(plain);
                Console.WriteLine($"Code={outcome.StatusCode}, Msg={outcome.StatusDescription}");
                if (!string.IsNullOrEmpty(outcome.ErrorMessage))
                    Console.WriteLine($"ERROR: {outcome.ErrorMessage}");

                Console.WriteLine("Headers:");
                foreach (var header in outcome.Headers)
                {
                    Console.WriteLine($"    {header.Key}: {header.Value}");
                }

                if (outcome.Body is null)
                {
                    Console.WriteLine("No body returned");
                }
                else
                {
                    Console.WriteLine(Bit.Describe("Response Body", outcome.Body));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to decode: {ex}");
            }
        }
        else
        {
            Console.WriteLine("Proxy call failed!");
            try
            {
                var str = cipher.Decode(Sync.Run(()=>response.Content.ReadAsByteArrayAsync()));
                Console.WriteLine(str);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to decode: {ex}");
            }
        }
    }
}