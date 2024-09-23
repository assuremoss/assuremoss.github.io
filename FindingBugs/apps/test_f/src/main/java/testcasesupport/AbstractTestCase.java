/*
@description This abstract class is the base for the majority of
test cases that are not Servlet or class based issue
*/

package testcasesupport;

public abstract class AbstractTestCase extends AbstractTestCaseBase
{
    public abstract void test_f1() throws Throwable;
    public abstract void test_f2() throws Throwable;
    public abstract void test_f3() throws Throwable;

    public void runTest(String className)
    {
        IO.writeLine("Starting tests for Class " + className);

        try
        {
            test_f1();

            IO.writeLine("Completed test_a1() for Class " + className);
        }
        catch (Throwable throwableException)
        {
            IO.writeLine("Caught a throwable from test_a1() for Class " + className);

            IO.writeLine("Throwable's message = " + throwableException.getMessage());

            StackTraceElement stackTraceElements[] = throwableException.getStackTrace();

            IO.writeLine("Stack trace below");

            for (StackTraceElement stackTraceElement : stackTraceElements)
            {
                IO.writeLine(stackTraceElement.toString());
            }
        }

        try
        {
            test_f2();

            IO.writeLine("Completed test_a2() for Class " + className);
        }
        catch (Throwable throwableException)
        {
            IO.writeLine("Caught a throwable from test_a2() for Class " + className);

            IO.writeLine("Throwable's message = " + throwableException.getMessage());

            StackTraceElement stackTraceElements[] = throwableException.getStackTrace();

            IO.writeLine("Stack trace below");

            for (StackTraceElement stackTraceElement : stackTraceElements)
            {
                IO.writeLine(stackTraceElement.toString());
            }
        }

        try
        {
            test_f3();

            IO.writeLine("Completed test_a3() for Class " + className);
        }
        catch (Throwable throwableException)
        {
            IO.writeLine("Caught a throwable from test_a3() for Class " + className);

            IO.writeLine("Throwable's message = " + throwableException.getMessage());

            StackTraceElement stackTraceElements[] = throwableException.getStackTrace();

            IO.writeLine("Stack trace below");

            for (StackTraceElement stackTraceElement : stackTraceElements)
            {
                IO.writeLine(stackTraceElement.toString());
            }
        }

    } /* runTest */
}
