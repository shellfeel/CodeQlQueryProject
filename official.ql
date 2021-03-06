/**
 * @name JNDI lookup with user-controlled name
 * @description Performing a JNDI lookup with a user-controlled name can lead to the download of an untrusted
 *              object and to execution of arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/log4j2/jndi-injection
 * @tags security
 *       external/cwe/cwe-074
 */

import java
import semmle.code.java.security.JndiInjectionQuery
import DataFlow::PathGraph
import semmle.code.java.security.JndiInjection

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

// new source 

class JndiLookup extends RefType{
    JndiLookup(){
        this.hasQualifiedName("org.apache.logging.log4j.core.lookup", "JndiLookup")
    }
}

class JndiLookupWithMethodLookup extends Method{
  JndiLookupWithMethodLookup(){
    this.getDeclaringType() instanceof JndiLookup and this.hasName("lookup")
  }
}

predicate isJndiManagerLookup(Parameter arg) {
    exists( Method method| method instanceof JndiLookupWithMethodLookup and method.getParameter(1) = arg )
}






class JdkLookup extends RefType{
    JdkLookup(){
        this.hasQualifiedName("javax.naming", "InitialContext")
    }
}

class MessagePatternConverter extends RefType{
  MessagePatternConverter(){
    this.hasQualifiedName("org.apache.logging.log4j.core.pattern", "MessagePatternConverter")
  }
}

class MessagePatternConverterWithFormat extends Method{
  MessagePatternConverterWithFormat(){
    this.getDeclaringType() instanceof MessagePatternConverter and this.hasName("format")
  }
}


predicate isMessagePatternConverterWithFormat(Parameter arg) {
    exists( Method method| method instanceof MessagePatternConverterWithFormat and method.getParameter(1) = arg )
}
// StrSubstitutor
class StrSubstitutor extends RefType{
  StrSubstitutor(){
    this.hasQualifiedName("org.apache.logging.log4j.core.lookup", "StrSubstitutor")
  }
}
// StrSubstitutor#substitute
class StrSubstitutorWithResolveVariable extends Method{
  StrSubstitutorWithResolveVariable(){
    this.getDeclaringType() instanceof StrSubstitutor and this.hasName("resolveVariable")
  }
}
predicate isStrSubstitutorWithresolveVariable(Parameter arg) {
    exists( Method method| method instanceof StrSubstitutorWithResolveVariable and method.getParameter(1) = arg )
}

// StrSubstitutor#substitute
class StrSubstitutorWithSubstitute extends Method{
  StrSubstitutorWithSubstitute(){
    this.getDeclaringType() instanceof StrSubstitutor and this.hasName("substitute") and this.isPrivate()
  }
}
predicate isStrSubstitutorWithSubstitute(Parameter arg) {
    exists( Method method| method instanceof StrSubstitutorWithSubstitute and method.getParameter(1) = arg )
}

predicate isVarNameExpr(Parameter arg) {
  exists(|arg.hasName("chars"))
}


class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }
  
  override predicate isSource(DataFlow::Node source) {
  //  exists(Parameter arg| isStrSubstitutorWithresolveVariable(arg) and source.asParameter() = arg )
  exists( |isMessagePatternConverterFormat(source.asParameter()))
  }
  
  override predicate isSink(DataFlow::Node sink) {
   sink instanceof JndiInjectionSink
  }


  // ???varNameExpr ??????source???
  predicate isLocalVarNameExpr(Expr arg) {
    exists(LocalVariableDecl varNameExpr | varNameExpr.hasName("chars") and varNameExpr.getDeclExpr() = arg and varNameExpr.getCallable().hasName("substitute") )
  }

  predicate isIsMatch(Expr chars) {
    exists(MethodAccess call| call.getCallee().hasName("getChars")  and call.getArgument(0) = chars and call.getCaller().hasName("substitute") )
  }
  // node 2 varNameExpr
  predicate isMessagePatternConverterFormat(Parameter arg) {
    exists( Method method | method.hasName("format") and method.getDeclaringType().hasQualifiedName("org.apache.logging.log4j.core.pattern", "MessagePatternConverter") and method.getParameter(1)=arg)
    
  }

   predicate isvarNameExprChar(Expr chars) {
    exists( MethodAccess call| call.getCallee().hasName("isMatch")  and call.getArgument(0) = chars and call.getCaller().hasName("substitute"))
    
  }
  //   override predicate isSanitizer(DataFlow::Node node) {
  //   node.getType() instanceof PrimitiveType or node.getType() instanceof BoxedType
  // }

    override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(|isIsMatch(node1.asExpr()) and isvarNameExprChar(node2.asExpr()))
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, MyConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "JNDI lookup might include name from $@.", source.getNode(),
  "this user input"
// select source,sink

// from LocalVariableDecl varNameExpr, Expr arg
// where varNameExpr.hasName("chars") and varNameExpr.getDeclExpr() = arg and varNameExpr.getCallable().hasName("substitute")
// select varNameExpr
// ,varNameExpr.getDeclExpr() 
// ,varNameExpr.getCallable()
// ,arg
// ,arg.getType().getName()

// from MethodAccess call,Parameter chars,Method method
// where call.getCallee().hasName("isMatch")  and call.getCallee().getParameter(0) = chars and call.getMethod()=method
// select call, method.getParameter(0),
// call.getCaller(),call.getCallee(),chars,call.getArgument(0)

// from Method method, Parameter arg
// where method.hasName("format") and method.getDeclaringType().hasQualifiedName("org.apache.logging.log4j.core.pattern", "MessagePatternConverter") and method.getParameter(1)=arg
// select method, arg