@extends('layouts.masterLayout')

@section('content')
<div class="section-header">
    <h1>All Users</h1>

</div>

<div class="table-responsive p-3 shadow rounded">
    <table class="table table-striped border table-hover" id="table-2">
        <thead>
            <tr>
                <th> S.R.</th>
                <th>Name</th>
                <th>Email</th>
                <th>Roles</th>
                {{-- <th>Joining date</th> --}}
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            @foreach ($users as $user)
            <tr class="align-middle">
                <td>{{ $loop->iteration }}</td>
                <td>{{ $user->name }}</td>
                <td>{{ $user->email }}</td>
                <td>
                    @if ($user->roles->isEmpty())
                    No roles assigned
                    @else
                    @foreach ($user->roles as $role)
                    <span class="badge bg-success">{{ $role->name }}</span>
                    @endforeach
                    @endif
                </td>
                {{-- <td>{{ $user->created_at->format('j F,Y') }}</td> --}}
                <td>
                    <a href="{{ route('admin.users.show', $user->id) }}" class="btn btn-primary">Roles</a>
                </td>
                @endforeach
            </tr>
        </tbody>
    </table>
</div>





@endsection