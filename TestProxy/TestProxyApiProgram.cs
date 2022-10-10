using System.Text;
using SkinnyJson;
using VirtualVpn.Helpers;
using VirtualVpn.Web;

namespace TestProxy;

class TestProxyApiProgram
{
    public static void Main(string[] args)
    {
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

        string messageSample = SampleCall();
        var proxyRequest = new HttpProxyRequest
        {
            Url = $"http://{MpesaTarget}:30009/iPG/c2b/multione", // who we want to talk to https://broker2.ipg.tz.vodafone.com:30009/iPG/c2b/multione
            ProxyLocalAddress = Hans, // who we are pretending to be
            Headers = { { "Accept", "text/xml" }, { "Host", "broker2.ipg.tz.vodafone.com" }, { "Content-Type", "text/xml" } },
            HttpMethod = "POST",
            Body = Encoding.UTF8.GetBytes(messageSample)
        };

        var proxyRequestBytes = cipher.Encode(Json.Freeze(proxyRequest));
        
        using var httpClient = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"http://{Gertrud}:8011/api/send");
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

    private static string SampleCall()
    {
        return @"<?xml version='1.0' encoding='UTF-8'?>
<mpesaBroker xmlns='http://inforwise.co.tz/broker/' version='2.0'>
    <request>
        <serviceProvider>
            <spId>757070</spId>
            <spPassword>test</spPassword> 
            <timestamp>20190221134033</timestamp>
        </serviceProvider>
        <transaction>
            <amount>0.0</amount>
            <comandId>Pay Bill</comandId>
            <initiator>+447597291842</initiator>
            <originatorConversationID>025d7efd-58bc-b06b-2aab91cde3b1</originatorConversationID>
            <recipient>400205</recipient>
            <mpesaReceipt>5BL716QnJbB</mpesaReceipt>
            <transactionDate>2019-02-21 12:40:27</transactionDate> 
            <accountReference>AR255758027779</accountReference>
            <transactionID>125189974</transactionID>
            <conversationID>025d7efd-58bc-b06b-2aab91cde3b1</conversationID>
        </transaction>
    </request>
</mpesaBroker>".Replace('\'', '"');
    }
}