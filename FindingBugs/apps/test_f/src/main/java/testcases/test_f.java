/**
 * @description
 * A test case with inter-file data exchange
 * Flow Variant: 01 Underline
 */


package testcases;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Level;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class test_f extends AbstractTestCase
{
    static class Container
    {
        public String containerOne;
    }

    public void test_f1() throws Throwable
    {
        // static data init
        String data = "";

        // retrieve property
        {
            Properties properties = new Properties();
            FileInputStream streamFileInput = null;

            try
            {
                streamFileInput = new FileInputStream("../common/config.properties");
                properties.load(streamFileInput);
                // read properties file data
                data = properties.getProperty("data");
            }
            catch (IOException exceptIO)
            {
                IO.logger.log(Level.WARNING, "Error with stream reading", exceptIO);
            }
            finally
            {
                // close stream
                try
                {
                    if (streamFileInput != null)
                    {
                        streamFileInput.close();
                    }
                }
                catch (IOException exceptIO)
                {
                    IO.logger.log(Level.WARNING, "Error closing FileInputStream", exceptIO);
                }
            }
        }

        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new test_f_utils()).execute_efficient(dataContainer);
    }

    public void test_f2() throws Throwable
    {
        // static data init
        String data = "this is a test * string! *";

        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new test_f_utils()).execute(dataContainer);
    }

    public void test_f3() throws Throwable
    {
        // static data init
        String data = "";

        // retrieve property
        {
            Properties properties = new Properties();
            FileInputStream streamFileInput = null;

            try
            {
                streamFileInput = new FileInputStream("../../user/config.properties");
                properties.load(streamFileInput);
                // read properties file data
                data = properties.getProperty("profile");
            }
            catch (IOException exceptIO)
            {
                IO.logger.log(Level.WARNING, "Error with stream reading", exceptIO);
            }
            finally
            {
                // close stream
                try
                {
                    if (streamFileInput != null)
                    {
                        streamFileInput.close();
                    }
                }
                catch (IOException exceptIO)
                {
                    IO.logger.log(Level.WARNING, "Error closing FileInputStream", exceptIO);
                }
            }
        }

        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new test_f_utils()).execute_unsafe(dataContainer);
    }

    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the testcases as one
     * application, which is how source code analysis tools are tested.
     */
    public static void main(String[] args) throws ClassNotFoundException,
           InstantiationException, IllegalAccessException
    {
        mainFromParent(args);
    }

}
