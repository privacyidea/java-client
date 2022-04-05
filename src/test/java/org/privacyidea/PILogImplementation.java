package org.privacyidea;

public class PILogImplementation implements IPILogger
{
    @Override
    public void log(String message)
    {
        System.out.println(message);
    }

    @Override
    public void error(String message)
    {
        System.out.println(message);
    }

    @Override
    public void log(Throwable t)
    {
        t.printStackTrace();
    }

    @Override
    public void error(Throwable t)
    {
        t.printStackTrace();
    }
}