package com.swabnet.platform.security.trusted.unitest;
import java.security.Principal;

public class SimplePrincipal implements Principal {
  private final String name;

  public SimplePrincipal(String name) {
    if(name == null) {
      throw new IllegalArgumentException("Null name");
    }
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public String toString() {
    return "ExamplePrinciapl: "+name;
  }

  public boolean equals(Object obj) {
    if(obj == null) return false;
    if(obj == this) return true;
    if(!(obj instanceof SimplePrincipal)) return false;
    SimplePrincipal another = (SimplePrincipal) obj;
    return name.equals(another.getName());
  }

  public int hasCode() {
    return name.hashCode();
  }
}

