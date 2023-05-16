import os
import argparse

from py2dotnetfile import DotNetPE


def main():
    parser = argparse.ArgumentParser(prog='dotnetfile_dump.py', description='Show .NET header information of assembly.')
    parser.add_argument(dest='input_file', type=str, help='Absolute file path of .NET assembly.')
    args = parser.parse_args()

    if not os.path.isabs(args.input_file):
        print('[-] Please provide absolute file path of .NET assembly.')
        return

    dotnet_file = DotNetPE(args.input_file)

    print('General information')
    print('\t.NET runtime target version: {}'.format(dotnet_file.get_runtime_target_version()))
    print('\tNumber of streams: {}'.format(dotnet_file.get_number_of_streams()))
    print('\tHas .NET resources: {}'.format(dotnet_file.has_resources()))
    print('\tIs a mixed .NET assembly (managed + native code): {}'.format(dotnet_file.is_mixed_assembly()))
    print('\tHas a native entry point: {}'.format(dotnet_file.has_native_entry_point()))
    print('\tIs a native image (precompiled) created by Ngen: {}'.format(dotnet_file.is_native_image()))
    print('\tIs a Windows Forms app: {}\n'.format(dotnet_file.is_windows_forms_app()))

    print('Anti analysis tricks')
    print('\t.NET data directory hidden in PE header: {}'.format(dotnet_file.AntiMetadataAnalysis.is_dotnet_data_directory_hidden))
    print('\tHas extra data at the end of the metadata header: {}'.format(dotnet_file.AntiMetadataAnalysis.has_metadata_table_extra_data))
    print('\tHas fake types that reference each other: {}'.format(dotnet_file.AntiMetadataAnalysis.has_self_referenced_typeref_entries))
    print('\tHas invalid entries in TypeRef table: {}'.format(dotnet_file.AntiMetadataAnalysis.has_invalid_typeref_entries))
    print('\tHas fake data streams: {}'.format(dotnet_file.AntiMetadataAnalysis.has_fake_data_streams))
    print('\tHas more than one row in Module table: {}'.format(dotnet_file.AntiMetadataAnalysis.module_table_has_multiple_rows))
    print('\tHas more than one row in Assembly table: {}'.format(dotnet_file.AntiMetadataAnalysis.assembly_table_has_multiple_rows))
    print('\tHas invalid entries in #Strings stream: {}'.format(dotnet_file.AntiMetadataAnalysis.has_invalid_strings_stream_entries))
    print()

    defined_entry_point = dotnet_file.Cor20Header.get_header_entry_point()
    if defined_entry_point:
        print('Cor20Header')
        if defined_entry_point.EntryPointType == 'Managed':
            print('\tManaged entry point:')
            print('\t\tMethod: {}'.format(defined_entry_point.Method))
            print('\t\tType: {}'.format(defined_entry_point.Type))
            print('\t\tNamespace: {}'.format(defined_entry_point.Namespace))
            if defined_entry_point.Signature:
                print('\t\tSignature:')
                print('\t\t\tParameter: {}'.format(defined_entry_point.Signature["parameter"]))
                print('\t\t\tReturn value: {}'.format(defined_entry_point.Signature["return"]))
                print('\t\t\tHas this pointer: {}'.format(defined_entry_point.Signature["hasthis"]))
        elif defined_entry_point.EntryPointType == 'Native':
            print('\tNative entry point:')
            print('\t\tAddress: {}'.format(defined_entry_point.Address))
        print()

    print('Stream names:')
    stream_names = dotnet_file.get_stream_names()
    for stream_name in stream_names:
        print('\t{}'.format(stream_name))
    print()

    print('All references:')
    all_references = dotnet_file.get_all_references()
    for reference in all_references:
        print('\t{}'.format(reference))
    print()

    print('#Strings stream strings:')
    strings_stream_strings = dotnet_file.get_strings_stream_strings()
    for string in strings_stream_strings:
        print('\t{}'.format(string))
    print()

    print('#US stream strings:')
    us_stream_strings = dotnet_file.get_user_stream_strings()
    for string in us_stream_strings:
        print('\t{}'.format(string))
    print()

    print('Existent metadata tables')
    available_tables = dotnet_file.existent_metadata_tables()
    for table in available_tables:
        print('\t{}'.format(table))
    print()

    if 'Module' in available_tables:
        print('Module')
        print('\tName: {}\n'.format(dotnet_file.Module.get_module_name()))

    if 'Assembly' in available_tables:
        print('Assembly')
        print('\tName: {}'.format(dotnet_file.Assembly.get_assembly_name()))
        print('\tCulture: {}'.format(dotnet_file.Assembly.get_assembly_culture()))
        assembly_version_info = dotnet_file.Assembly.get_assembly_version_information()
        if assembly_version_info:
            print('\tVersion information: {}.{}.{}.{}'.format(assembly_version_info.BuildNumber,
                                                              assembly_version_info.MajorVersion,
                                                              assembly_version_info.MinorVersion,
                                                              assembly_version_info.RevisionNumber))
        print()

    if 'AssemblyRef' in available_tables:
        print('AssemblyRef')
        print('\tNames:')
        assembly_names = dotnet_file.AssemblyRef.get_assemblyref_names()
        for assembly_name in assembly_names:
            print('\t\t{}'.format(assembly_name))
        print('\tCultures:')
        culture_names = dotnet_file.AssemblyRef.get_assemblyref_cultures()
        for culture_name in culture_names:
            print('\t\t{}'.format(culture_name))
        print()

    if 'ModuleRef' in available_tables:
        print('ModuleRef')
        print('\tUnmanaged module names (normalized):')
        unmanaged_modules = dotnet_file.ModuleRef.get_unmanaged_module_names(dotnet_file.Type.UnmanagedModules.NORMALIZED)
        for unmanaged_module in unmanaged_modules:
            print('\t\t{}'.format(unmanaged_module))
        print()

    if 'ImplMap' in available_tables:
        print('ImplMap')
        print('\tUnmanaged functions:')
        unmanaged_functions = dotnet_file.ImplMap.get_unmanaged_functions()
        for unmanaged_function in unmanaged_functions:
            print('\t\t{}'.format(unmanaged_function))

    if 'TypeRef' in available_tables:
        print('TypeRef')
        print('\tReferenced type names:')
        ref_type_names = dotnet_file.TypeRef.get_typeref_names()
        for ref_type_name in ref_type_names:
            print('\t\t{}'.format(ref_type_name))

        print('\tTypeRef hash (unsorted):')
        print('\t\tSHA256: {}'.format(dotnet_file.TypeRef.get_typeref_hash()))

        print('\tTypeRef hash (sorted, include self-referenced entries):')
        print('\t\tSHA256: {}\n'.format(dotnet_file.TypeRef.get_typeref_hash(dotnet_file.Type.Hash.SHA256, False, True)))

    if 'TypeDef' in available_tables:
        print('TypeDef')
        print('\tType names:')
        type_names = dotnet_file.TypeDef.get_type_names()
        for type_name in type_names:
            print('\t\t{}'.format(type_name))
        print()

    if 'MethodDef' in available_tables:
        print('MethodDef')
        print('\tMethod names:')
        method_names = dotnet_file.MethodDef.get_method_names()
        for method_name in method_names:
            print('\t\t{}'.format(method_name))

        print('\tPossible method entry points:')
        entry_points = dotnet_file.MethodDef.get_entry_points()
        for entry_point in entry_points:
            print('\t\tMethod: {}'.format(entry_point.Method))
            print('\t\tType: {}'.format(entry_point.Type))
            print('\t\tNamespace: {}'.format(entry_point.Namespace))
            if entry_point.Signature:
                print('\t\tSignature:')
                print('\t\t\t\tParameter: {}'.format(entry_point.Signature["parameter"]))
                print('\t\t\t\tReturn value: {}'.format(entry_point.Signature["return"]))
                print('\t\t\t\tHas this pointer: {}'.format(entry_point.Signature["hasthis"]))
            print('\t\t---')
        print()

    if 'MemberRef' in available_tables:
        print('MemberRef')
        print('\tNames:')
        memberref_names = dotnet_file.MemberRef.get_memberref_names(deduplicate=True)
        for memberref_name in memberref_names:
            print('\t\t{}'.format(memberref_name))

        print('\tMemberRef hash (unsorted):')
        print('\t\tSHA256: {}').format(dotnet_file.MemberRef.get_memberref_hash())

        print('\tMemberRef hash (sorted):')
        print('\t\tSHA256: {}\n'.format(dotnet_file.MemberRef.get_memberref_hash(strings_sorted=True)))

    if 'Event' in available_tables:
        print('Event')
        print('\tNames:')
        event_names = dotnet_file.Event.get_event_names()
        for event_name in event_names:
            print('\t\t{}'.format(event_name))
        print()

    if 'ManifestResource' in available_tables:
        print('ManifestResource')
        print('\tNames:')
        resource_names = dotnet_file.ManifestResource.get_resource_names()
        for resource_name in resource_names:
            print('\t\t{}'.format(resource_name))
        print()

    print('Resources:')
    resource_data = dotnet_file.get_resources()
    for data in resource_data:
        for resource_item in data.items():
            if resource_item[0] == 'SubResources':
                if resource_item[1]:
                    print('\tSubResources:')
                    for sub_resource in resource_item[1]:
                        for sub_resource_item in sub_resource.items():
                            print('\t\t{}: {}'.format(sub_resource_item[0], sub_resource_item[1]))
                        print('\t\t---')
            else:
                print('\t{}: {}'.format(resource_item[0],resource_item[1]))
        print('\t---')


if __name__ == '__main__':
    main()
