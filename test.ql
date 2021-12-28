// /**
//  * * @name Unsafe XML deserialization
//  * @kind path-problem
//  * @id java/unsafe-deserialization
//  */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph


// sink点
predicate isRequestUrl(Expr arg) {
    exists( MethodAccess call|call.getArgument(0)=arg and call.getMethod().hasName("url"))
}
// source 点

class SsrfDemo extends RefType{
    SsrfDemo(){
        this.hasName("SsrfDemo")
    }
}
class SsrfDemoGet extends Method{
    SsrfDemoGet(){
        this.hasName("get") and this.getDeclaringType() instanceof SsrfDemo
    }
}

predicate isMainGet(Expr arg) {
    exists(MethodAccess call | call.getMethod() instanceof SsrfDemoGet and call.getArgument(0) = arg)
}

class MyConfig extends DataFlow::Configuration{


    MyConfig(){
        this = "MyConfig"
    }
  /**
   * Holds if `source` is a relevant data flow source.
   */
  override predicate isSource(DataFlow::Node source){
    exists( Expr arg | source.asExpr() =  arg and isMainGet(arg))
  }

  /**
   * Holds if `sink` is a relevant data flow sink.
   */
  override predicate isSink(DataFlow::Node sink){
    exists(Expr arg | sink.asExpr() = arg and isRequestUrl(arg))
  }
}




from DataFlow::PathNode sink,DataFlow::PathNode source, MyConfig config
where  config.hasFlowPath(source, sink)
select source, sink