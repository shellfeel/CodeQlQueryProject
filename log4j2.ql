/**
 * @name log4j2 Jndi injection
 * @kind path-problem
 * @id java/jndi-injection-log4j2
 */


import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph
import semmle.code.java.security.JndiInjectionQuery


// // source - jndiName
// predicate isJndiName(Method ) {
//     exists(MethodAccess call| call.getMethod().hasName("convertJndiName"))
// }


// source
predicate isJndiManager(Parameter arg) {
    exists( Method method| method instanceof JndiManagerLookup and method.getParameter(0) = arg )
}

class JndiManager extends RefType{
    JndiManager(){
        this.hasQualifiedName("org.apache.logging.log4j.core.net", "JndiManager")
    }
}

class JndiManagerLookup extends Method{
    JndiManagerLookup(){
        this.getDeclaringType() instanceof JndiManager and this.hasName("lookup")
    }
}

// sink
class JndiLookup extends RefType{
    JndiLookup(){
        this.hasQualifiedName("org.apache.logging.log4j.core.lookup", "JndiLookup")
    }
}
class JndiLookupLookup extends Method{
    JndiLookupLookup(){
        this.getDeclaringType() instanceof JndiLookup and this.hasName("lookup")
    }
}

predicate isJndiLookupLookup(Parameter arg) {
    exists(Method method | method instanceof JndiLookupLookup and method.getParameter(1) = arg)
}


// 全局数据流
class Log4j2JndiInjectionDataFlow extends TaintTracking::Configuration{
      /**
   * Holds if `source` is a relevant data flow source.
   */
  Log4j2JndiInjectionDataFlow(){
      this = "Log4j2JndiInjectionDataFlow"
  }
  override predicate isSource(DataFlow::Node source){
    exists(Parameter arg| isJndiManager(arg) and source.asParameter() = arg )
  }

  /**
   * Holds if `sink` is a relevant data flow sink.
   */
  override predicate isSink(DataFlow::Node sink){
    exists(Parameter arg| isJndiLookupLookup(arg) and sink.asParameter() = arg)
  }
   override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
       none()
    }
}

// 官网数据流
class MyConfig extends JndiInjectionFlowConfig{
    MyConfig(){this = "MyConfig"}
    override predicate isSource(DataFlow::Node source) { 
         exists(Parameter arg| isJndiManager(arg) and source.asParameter() = arg )
    }
}



//  findsource
// from Log4j2JndiInjectionDataFlow config, DataFlow::PathNode sink, DataFlow::PathNode source
// where config.hasFlowPath(source, sink)
// select sink, source

// class MyConfig extends JndiInjectionFlowConfig{
//     MyConfig(){this = "MyConfig"}
//     override predicate isSource(DataFlow::Node source) { 
//          exists(Parameter arg| isJndiManager(arg) and source.asParameter() = arg )
//     }
// }

// //  findsource
// from Log4j2JndiInjectionDataFlow config, DataFlow::PathNode sink, DataFlow::PathNode source
// where config.hasFlowPath(source, sink)
// select sink.getNode(), source, sink, "JNDI lookup might include name from $@.", source.getNode(),
//   "this user input"



from DataFlow::PathNode source, DataFlow::PathNode sink, MyConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "JNDI lookup might include name from $@.", source.getNode(),
  "this user input"