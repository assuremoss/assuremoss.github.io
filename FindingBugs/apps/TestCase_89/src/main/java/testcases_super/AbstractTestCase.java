/*
@description This abstract class is the base for the majority of 
test cases that are not Servlet or class based issue

*/

package testcases_super;

public abstract class AbstractTestCase extends AbstractTestCaseBase 
{
    public abstract void very_intelligent_query() throws Throwable;
    
    public void runTest(String className) 
    {
        IO.writeLine("Starting tests for Class " + className);
        try 
        {
            very_intelligent_query();
            
            IO.writeLine("Completed very_intelligent_query() for Class " + className);
        } 
        catch (Throwable throwableException) 
        {
            IO.writeLine("Caught a throwable from very_intelligent_query() for Class " + className);

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
