/**
 * @description
 * A test case with inter-file data exchange
 * Utilities
 */

package testcases;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;

import testcasesupport.IO;

public class test_f_utils
{
    // fast query execution, requires safe source
    public void execute_efficient(test_f.Container dataContainer ) throws Throwable
    {
        String data = dataContainer.containerOne;

        Connection dbConnection = null;
        PreparedStatement sqlStatement = null;
        String SQLquery = "insert into users (status) values ('updated') where name=?";
        
        try
        {
            dbConnection = IO.getDBConnection();
            sqlStatement = dbConnection.prepareStatement(SQLquery);
            // sqlStatement.setCursorName(data);
            sqlStatement.setString(1, data);
            
            // create query with passed query string
            int rowCount = sqlStatement.executeUpdate();

            IO.writeLine("Updated " + rowCount + " rows successfully.");
        }
        catch (SQLException exceptSql)
        {
            IO.logger.log(Level.WARNING, "Error getting database connection", exceptSql);
        }
        finally
        {
            try
            {
                if (sqlStatement != null)
                {
                    sqlStatement.close();
                }
            }
            catch (SQLException exceptSql)
            {
                IO.logger.log(Level.WARNING, "Error closing Statement", exceptSql);
            }

            try
            {
                if (dbConnection != null)
                {
                    dbConnection.close();
                }
            }
            catch (SQLException exceptSql)
            {
                IO.logger.log(Level.WARNING, "Error closing Connection", exceptSql);
            }
        }

    }

    // standard query execution
    public void execute(test_f.Container dataContainer ) throws Throwable
    {
        String data = dataContainer.containerOne;

        Connection dbConnection = null;
        Statement sqlStatement = null;

        try
        {
            dbConnection = IO.getDBConnection();
            sqlStatement = dbConnection.createStatement();

            // create query with passed query string
            int rowCount = sqlStatement.executeUpdate("insert into users (status) values ('updated') where name='"+data+"'");

            IO.writeLine("Updated " + rowCount + " rows successfully.");
        }
        catch (SQLException exceptSql)
        {
            IO.logger.log(Level.WARNING, "Error getting database connection", exceptSql);
        }
        finally
        {
            try
            {
                if (sqlStatement != null)
                {
                    sqlStatement.close();
                }
            }
            catch (SQLException exceptSql)
            {
                IO.logger.log(Level.WARNING, "Error closing Statement", exceptSql);
            }

            try
            {
                if (dbConnection != null)
                {
                    dbConnection.close();
                }
            }
            catch (SQLException exceptSql)
            {
                IO.logger.log(Level.WARNING, "Error closing Connection", exceptSql);
            }
        }

    }

    // test case by junior dev, don't trust it
    public void execute_unsafe(test_f.Container dataContainer ) throws Throwable
    {
        String data = dataContainer.containerOne;

        Connection dbConnection = null;
        Statement sqlStatement = null;

        try
        {
            dbConnection = IO.getDBConnection();
            sqlStatement = (Statement) dbConnection.prepareStatement("insert into users (status) values ('updated') where name=?");
            ((PreparedStatement) sqlStatement).setString(1, data);

            int rowCount = ((PreparedStatement) sqlStatement).executeUpdate();

            IO.writeLine("Updated " + rowCount + " rows successfully.");
        }
        catch (SQLException exceptSql)
        {
            IO.logger.log(Level.WARNING, "Error getting database connection", exceptSql);
        }
        finally
        {
            try
            {
                if (sqlStatement != null)
                {
                    sqlStatement.close();
                }
            }
            catch (SQLException exceptSql)
            {
                IO.logger.log(Level.WARNING, "Error closing PreparedStatement", exceptSql);
            }

            try
            {
                if (dbConnection != null)
                {
                    dbConnection.close();
                }
            }
            catch (SQLException exceptSql)
            {
                IO.logger.log(Level.WARNING, "Error closing Connection", exceptSql);
            }
        }

    }
}
