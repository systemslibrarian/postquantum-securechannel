using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Public-API freeze guard for 1.0. Reflects over every exported type and member of the
/// <c>PostQuantum.SecureChannel</c> assembly, renders a stable signature for each, and compares the
/// sorted result to a checked-in baseline (<c>PublicApi.approved.txt</c>). Any addition, removal, or
/// signature change to the public surface fails this test — which for a 1.0 package under Semantic
/// Versioning is the point: breaking the surface must be a deliberate, reviewed act (regenerate the
/// baseline and bump the major version), never an accident.
///
/// <para>
/// To intentionally change the public API: delete <c>PublicApi.approved.txt</c> and re-run (it
/// re-bootstraps), or copy <c>PublicApi.received.txt</c> over it, then review the diff in the commit.
/// </para>
/// </summary>
public class PublicApiSurfaceTests
{
    [Fact]
    public void PublicApi_MatchesApprovedBaseline()
    {
        string actual = RenderPublicApi(typeof(PqSecureChannel).Assembly);

        string dir = Path.GetDirectoryName(ThisFilePath())!;
        string approvedPath = Path.Combine(dir, "PublicApi.approved.txt");
        string receivedPath = Path.Combine(dir, "PublicApi.received.txt");

        if (!File.Exists(approvedPath))
        {
            // Bootstrap: first run records the current surface as the baseline and passes.
            File.WriteAllText(approvedPath, actual);
            return;
        }

        string approved = File.ReadAllText(approvedPath).Replace("\r\n", "\n");
        actual = actual.Replace("\r\n", "\n");

        if (approved != actual)
        {
            File.WriteAllText(receivedPath, actual);
        }
        else if (File.Exists(receivedPath))
        {
            File.Delete(receivedPath);
        }

        Assert.Equal(approved, actual);
    }

    private static string ThisFilePath([CallerFilePath] string path = "") => path;

    private static string RenderPublicApi(Assembly assembly)
    {
        var lines = new List<string>();

        foreach (var type in assembly.GetExportedTypes())
        {
            string typeName = FriendlyName(type);
            lines.Add($"{TypeKind(type)} {typeName}");

            const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic
                | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

            foreach (var member in type.GetMembers(flags))
            {
                string? sig = RenderMember(member);
                if (sig is not null)
                {
                    lines.Add($"{typeName} :: {sig}");
                }
            }
        }

        lines.Sort(StringComparer.Ordinal);
        return string.Join("\n", lines) + "\n";
    }

    private static string TypeKind(Type t) =>
        t.IsEnum ? "enum"
        : t.IsValueType ? "struct"
        : t.IsInterface ? "interface"
        : "class";

    /// <summary>Returns the signature for members that form the public/protected surface, or null to skip.</summary>
    private static string? RenderMember(MemberInfo member)
    {
        // Skip compiler-generated members (backing fields, record clone helpers, etc.).
        if (member.Name.Contains('<') || member.GetCustomAttribute<CompilerGeneratedAttribute>() is not null)
        {
            return null;
        }

        switch (member)
        {
            case FieldInfo f when member.DeclaringType!.IsEnum:
                return f.IsLiteral ? $"{f.Name} = {f.GetRawConstantValue()}" : null;

            case FieldInfo f when IsVisible(f.IsPublic, f.IsFamily, f.IsFamilyOrAssembly):
                string fieldMod = f.IsLiteral ? "const " : f.IsStatic ? "static " : "";
                string readonlyMod = f is { IsInitOnly: true, IsStatic: false } or { IsInitOnly: true, IsStatic: true } ? "readonly " : "";
                return $"field {fieldMod}{readonlyMod}{FriendlyName(f.FieldType)} {f.Name}";

            case PropertyInfo p:
                var getter = p.GetMethod;
                var setter = p.SetMethod;
                bool getVisible = getter is not null && IsVisible(getter.IsPublic, getter.IsFamily, getter.IsFamilyOrAssembly);
                bool setVisible = setter is not null && IsVisible(setter.IsPublic, setter.IsFamily, setter.IsFamilyOrAssembly);
                if (!getVisible && !setVisible)
                {
                    return null;
                }

                var accessors = new List<string>();
                if (getVisible) accessors.Add("get;");
                if (setVisible) accessors.Add(setter!.ReturnParameter.GetRequiredCustomModifiers()
                    .Any(m => m.Name == "IsExternalInit") ? "init;" : "set;");
                string indexer = p.GetIndexParameters().Length > 0
                    ? $"[{RenderParams(p.GetIndexParameters())}]" : "";
                bool propStatic = (getter ?? setter)!.IsStatic;
                return $"{(propStatic ? "static " : "")}{FriendlyName(p.PropertyType)} {p.Name}{indexer} {{ {string.Join(" ", accessors)} }}";

            case ConstructorInfo c when IsVisible(c.IsPublic, c.IsFamily, c.IsFamilyOrAssembly):
                return $".ctor({RenderParams(c.GetParameters())})";

            case MethodInfo m when IsVisible(m.IsPublic, m.IsFamily, m.IsFamilyOrAssembly):
                // Skip property/event accessors (rendered via the property/event); keep operators.
                if (m.IsSpecialName &&
                    (m.Name.StartsWith("get_") || m.Name.StartsWith("set_") ||
                     m.Name.StartsWith("add_") || m.Name.StartsWith("remove_")))
                {
                    return null;
                }

                string methodStatic = m.IsStatic ? "static " : "";
                string generics = m.IsGenericMethodDefinition
                    ? $"<{string.Join(", ", m.GetGenericArguments().Select(a => a.Name))}>" : "";
                return $"{methodStatic}{FriendlyName(m.ReturnType)} {m.Name}{generics}({RenderParams(m.GetParameters())})";

            case EventInfo e:
                var add = e.AddMethod;
                if (add is null || !IsVisible(add.IsPublic, add.IsFamily, add.IsFamilyOrAssembly))
                {
                    return null;
                }

                return $"event {FriendlyName(e.EventHandlerType!)} {e.Name}";

            default:
                return null;
        }
    }

    private static bool IsVisible(bool isPublic, bool isFamily, bool isFamilyOrAssembly)
        => isPublic || isFamily || isFamilyOrAssembly;

    private static string RenderParams(ParameterInfo[] parameters)
        => string.Join(", ", parameters.Select(p =>
        {
            string modifier = p.ParameterType.IsByRef
                ? (p.IsOut ? "out " : p.IsIn ? "in " : "ref ")
                : "";
            string defaultVal = p.HasDefaultValue ? " = " + (p.DefaultValue?.ToString() ?? "null") : "";
            return $"{modifier}{FriendlyName(p.ParameterType)} {p.Name}{defaultVal}";
        }));

    private static string FriendlyName(Type t)
    {
        if (t.IsByRef)
        {
            return FriendlyName(t.GetElementType()!);
        }

        if (t.IsArray)
        {
            return FriendlyName(t.GetElementType()!) + "[]";
        }

        if (t.IsGenericType)
        {
            var def = t.GetGenericTypeDefinition();
            if (def == typeof(Nullable<>))
            {
                return FriendlyName(t.GetGenericArguments()[0]) + "?";
            }

            string name = t.Name;
            int tick = name.IndexOf('`');
            if (tick >= 0)
            {
                name = name[..tick];
            }

            string args = string.Join(", ", t.GetGenericArguments().Select(FriendlyName));
            return $"{name}<{args}>";
        }

        return t.Name switch
        {
            "Void" => "void",
            "Boolean" => "bool",
            "Byte" => "byte",
            "Int32" => "int",
            "Int64" => "long",
            "UInt32" => "uint",
            "UInt64" => "ulong",
            "String" => "string",
            "Object" => "object",
            _ => t.Name,
        };
    }
}
