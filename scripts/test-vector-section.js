export default function testVectorSection(entry) {
  const { alg } = entry;
  return `## ${alg}
{: toc="exclude"}

~~~ json
{::include examples/jwks/${alg}.json}
~~~
{: title="${alg} Private JWK"}

~~~ json
{::include examples/jwe/${alg}-flattened.json}
~~~
{: title="${alg} Flattened JWE JSON Serialization"}

~~~
{::include examples/jwe/${alg}-compact.txt}
~~~
{: title="${alg} JWE Compact Serialization"}`;
}
