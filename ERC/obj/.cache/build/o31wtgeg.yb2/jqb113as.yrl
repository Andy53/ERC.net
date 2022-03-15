<!DOCTYPE html>
<!--[if IE]><![endif]-->
<html>
  
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title>Class HeapInfo
   </title>
    <meta name="viewport" content="width=device-width">
    <meta name="title" content="Class HeapInfo
   ">
    <meta name="generator" content="docfx 2.59.0.0">
    
    <link rel="shortcut icon" href="../favicon.ico">
    <link rel="stylesheet" href="../styles/docfx.vendor.css">
    <link rel="stylesheet" href="../styles/docfx.css">
    <link rel="stylesheet" href="../styles/main.css">
    <meta property="docfx:navrel" content="../toc.html">
    <meta property="docfx:tocrel" content="toc.html">
    
    
    
  </head>
  <body data-spy="scroll" data-target="#affix" data-offset="120">
    <div id="wrapper">
      <header>
        
        <nav id="autocollapse" class="navbar navbar-inverse ng-scope" role="navigation">
          <div class="container">
            <div class="navbar-header">
              <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#navbar">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
              </button>
              
              <a class="navbar-brand" href="../index.html">
                <img id="logo" class="svg" src="../logo.svg" alt="">
              </a>
            </div>
            <div class="collapse navbar-collapse" id="navbar">
              <form class="navbar-form navbar-right" role="search" id="search">
                <div class="form-group">
                  <input type="text" class="form-control" id="search-query" placeholder="Search" autocomplete="off">
                </div>
              </form>
            </div>
          </div>
        </nav>
        
        <div class="subnav navbar navbar-default">
          <div class="container hide-when-search" id="breadcrumb">
            <ul class="breadcrumb">
              <li></li>
            </ul>
          </div>
        </div>
      </header>
      <div role="main" class="container body-content hide-when-search">
        
        <div class="sidenav hide-when-search">
          <a class="btn toc-toggle collapse" data-toggle="collapse" href="#sidetoggle" aria-expanded="false" aria-controls="sidetoggle">Show / Hide Table of Contents</a>
          <div class="sidetoggle collapse" id="sidetoggle">
            <div id="sidetoc"></div>
          </div>
        </div>
        <div class="article row grid-right">
          <div class="col-md-10">
            <article class="content wrap" id="_content" data-uid="ERC.HeapInfo">
  
  
  <h1 id="ERC_HeapInfo" data-uid="ERC.HeapInfo" class="text-break">Class HeapInfo
  </h1>
  <div class="markdown level0 summary"></div>
  <div class="markdown level0 conceptual"></div>
  <div class="inheritance">
    <h5>Inheritance</h5>
    <div class="level0"><span class="xref">System.Object</span></div>
    <div class="level1"><span class="xref">HeapInfo</span></div>
  </div>
  <div class="inheritedMembers">
    <h5>Inherited Members</h5>
    <div>
      <span class="xref">System.Object.ToString()</span>
    </div>
    <div>
      <span class="xref">System.Object.Equals(System.Object)</span>
    </div>
    <div>
      <span class="xref">System.Object.Equals(System.Object, System.Object)</span>
    </div>
    <div>
      <span class="xref">System.Object.ReferenceEquals(System.Object, System.Object)</span>
    </div>
    <div>
      <span class="xref">System.Object.GetHashCode()</span>
    </div>
    <div>
      <span class="xref">System.Object.GetType()</span>
    </div>
    <div>
      <span class="xref">System.Object.MemberwiseClone()</span>
    </div>
  </div>
  <h6><strong>Namespace</strong>: <a class="xref" href="ERC.html">ERC</a></h6>
  <h6><strong>Assembly</strong>: ERC.Net.dll</h6>
  <h5 id="ERC_HeapInfo_syntax">Syntax</h5>
  <div class="codewrapper">
    <pre><code class="lang-csharp hljs">public class HeapInfo</code></pre>
  </div>
  <h3 id="constructors">Constructors
  </h3>
  
  
  <a id="ERC_HeapInfo__ctor_" data-uid="ERC.HeapInfo.#ctor*"></a>
  <h4 id="ERC_HeapInfo__ctor_ERC_ProcessInfo_" data-uid="ERC.HeapInfo.#ctor(ERC.ProcessInfo)">HeapInfo(ProcessInfo)</h4>
  <div class="markdown level1 summary"></div>
  <div class="markdown level1 conceptual"></div>
  <h5 class="decalaration">Declaration</h5>
  <div class="codewrapper">
    <pre><code class="lang-csharp hljs">public HeapInfo(ProcessInfo info)</code></pre>
  </div>
  <h5 class="parameters">Parameters</h5>
  <table class="table table-bordered table-striped table-condensed">
    <thead>
      <tr>
        <th>Type</th>
        <th>Name</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><a class="xref" href="ERC.ProcessInfo.html">ProcessInfo</a></td>
        <td><span class="parametername">info</span></td>
        <td></td>
      </tr>
    </tbody>
  </table>
  <h3 id="methods">Methods
  </h3>
  
  
  <a id="ERC_HeapInfo_HeapIDs_" data-uid="ERC.HeapInfo.HeapIDs*"></a>
  <h4 id="ERC_HeapInfo_HeapIDs" data-uid="ERC.HeapInfo.HeapIDs">HeapIDs()</h4>
  <div class="markdown level1 summary"></div>
  <div class="markdown level1 conceptual"></div>
  <h5 class="decalaration">Declaration</h5>
  <div class="codewrapper">
    <pre><code class="lang-csharp hljs">public ErcResult&lt;List&lt;ulong&gt;&gt; HeapIDs()</code></pre>
  </div>
  <h5 class="returns">Returns</h5>
  <table class="table table-bordered table-striped table-condensed">
    <thead>
      <tr>
        <th>Type</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><a class="xref" href="ERC.ErcResult-1.html">ErcResult</a>&lt;<span class="xref">System.Collections.Generic.List</span>&lt;<span class="xref">System.UInt64</span>&gt;&gt;</td>
        <td></td>
      </tr>
    </tbody>
  </table>
  
  
  <a id="ERC_HeapInfo_HeapStatistics_" data-uid="ERC.HeapInfo.HeapStatistics*"></a>
  <h4 id="ERC_HeapInfo_HeapStatistics_System_Boolean_System_UInt64_System_String_" data-uid="ERC.HeapInfo.HeapStatistics(System.Boolean,System.UInt64,System.String)">HeapStatistics(Boolean, UInt64, String)</h4>
  <div class="markdown level1 summary"></div>
  <div class="markdown level1 conceptual"></div>
  <h5 class="decalaration">Declaration</h5>
  <div class="codewrapper">
    <pre><code class="lang-csharp hljs">public ErcResult&lt;List&lt;string&gt;&gt; HeapStatistics(bool extended = false, ulong heapID = 0UL, string hexStartAddress = &quot;&quot;)</code></pre>
  </div>
  <h5 class="parameters">Parameters</h5>
  <table class="table table-bordered table-striped table-condensed">
    <thead>
      <tr>
        <th>Type</th>
        <th>Name</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="xref">System.Boolean</span></td>
        <td><span class="parametername">extended</span></td>
        <td></td>
      </tr>
      <tr>
        <td><span class="xref">System.UInt64</span></td>
        <td><span class="parametername">heapID</span></td>
        <td></td>
      </tr>
      <tr>
        <td><span class="xref">System.String</span></td>
        <td><span class="parametername">hexStartAddress</span></td>
        <td></td>
      </tr>
    </tbody>
  </table>
  <h5 class="returns">Returns</h5>
  <table class="table table-bordered table-striped table-condensed">
    <thead>
      <tr>
        <th>Type</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><a class="xref" href="ERC.ErcResult-1.html">ErcResult</a>&lt;<span class="xref">System.Collections.Generic.List</span>&lt;<span class="xref">System.String</span>&gt;&gt;</td>
        <td></td>
      </tr>
    </tbody>
  </table>
  
  
  <a id="ERC_HeapInfo_SearchHeap_" data-uid="ERC.HeapInfo.SearchHeap*"></a>
  <h4 id="ERC_HeapInfo_SearchHeap_System_Byte___System_UInt64_System_String_" data-uid="ERC.HeapInfo.SearchHeap(System.Byte[],System.UInt64,System.String)">SearchHeap(Byte[], UInt64, String)</h4>
  <div class="markdown level1 summary"><p sourcefile="api/ERC.HeapInfo.yml" sourcestartlinenumber="2">Searches heap entries for a specified pattern. Returns pointers to all instances of the pattern. If heapID and startAddress are both supplied heapID takes precedence.</p>
</div>
  <div class="markdown level1 conceptual"></div>
  <h5 class="decalaration">Declaration</h5>
  <div class="codewrapper">
    <pre><code class="lang-csharp hljs">public ErcResult&lt;List&lt;Tuple&lt;IntPtr, IntPtr, IntPtr&gt;&gt;&gt; SearchHeap(byte[] searchBytes, ulong heapID = 0UL, string hexStartAddress = &quot;&quot;)</code></pre>
  </div>
  <h5 class="parameters">Parameters</h5>
  <table class="table table-bordered table-striped table-condensed">
    <thead>
      <tr>
        <th>Type</th>
        <th>Name</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="xref">System.Byte</span>[]</td>
        <td><span class="parametername">searchBytes</span></td>
        <td><p sourcefile="api/ERC.HeapInfo.yml" sourcestartlinenumber="1">byte array containing the pattern to search for</p>
</td>
      </tr>
      <tr>
        <td><span class="xref">System.UInt64</span></td>
        <td><span class="parametername">heapID</span></td>
        <td><p sourcefile="api/ERC.HeapInfo.yml" sourcestartlinenumber="1">ID of the heap to be searched(Optional)</p>
</td>
      </tr>
      <tr>
        <td><span class="xref">System.String</span></td>
        <td><span class="parametername">hexStartAddress</span></td>
        <td><p sourcefile="api/ERC.HeapInfo.yml" sourcestartlinenumber="1">Start address of the heap entry to be searched in hexadecimal(Optional)</p>
</td>
      </tr>
    </tbody>
  </table>
  <h5 class="returns">Returns</h5>
  <table class="table table-bordered table-striped table-condensed">
    <thead>
      <tr>
        <th>Type</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><a class="xref" href="ERC.ErcResult-1.html">ErcResult</a>&lt;<span class="xref">System.Collections.Generic.List</span>&lt;<span class="xref">System.Tuple</span>&lt;<span class="xref">System.IntPtr</span>, <span class="xref">System.IntPtr</span>, <span class="xref">System.IntPtr</span>&gt;&gt;&gt;</td>
        <td><p sourcefile="api/ERC.HeapInfo.yml" sourcestartlinenumber="1">Returns an ERCResult of IntPtr containing pointers to all instances of the pattern found.</p>
</td>
      </tr>
    </tbody>
  </table>
</article>
          </div>
          
          <div class="hidden-sm col-md-2" role="complementary">
            <div class="sideaffix">
              <div class="contribution">
                <ul class="nav">
                </ul>
              </div>
              <nav class="bs-docs-sidebar hidden-print hidden-xs hidden-sm affix" id="affix">
                <h5>In This Article</h5>
                <div></div>
              </nav>
            </div>
          </div>
        </div>
      </div>
      
      <footer>
        <div class="grad-bottom"></div>
        <div class="footer">
          <div class="container">
            <span class="pull-right">
              <a href="#top">Back to top</a>
            </span>
            
            <span>Generated by <strong>DocFX</strong></span>
          </div>
        </div>
      </footer>
    </div>
    
    <script type="text/javascript" src="../styles/docfx.vendor.js"></script>
    <script type="text/javascript" src="../styles/docfx.js"></script>
    <script type="text/javascript" src="../styles/main.js"></script>
  </body>
</html>
