package org.privacyidea;

public class PIError
{
    public PIError(int code, String message)
    {
        this.code = code;
        this.message = message;
    }

    public int code = 0;
    public String message = "";
}
