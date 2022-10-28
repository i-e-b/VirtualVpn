namespace VirtualVpn.Logging;

public class PendingLogLine
{
    public DateTime Date { get; set; }
    public LogLevel Level { get; set; }
    public string Message { get; set; }="";
}