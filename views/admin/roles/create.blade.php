@extends('layouts.masterLayout')

@section('title','Create Role')
@section('content')

<div class="section-header">
    <h1>Create New Role</h1>
</div>

<div class="py-1">
    <div class="container">
        <div class="card">
            <div class="card-header">
                <a href="{{ url('roles') }}" class="btn btn-success">Role Index</a>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <form method="POST" action="{{ route('admin.roles.store') }}">
                            @csrf
                            <div class="mb-3">
                                <label for="name" class="form-label">Role name</label>
                                <input type="text" id="name" name="name" class="form-control" />
                                @error('name')
                                <span class="text-danger">{{ $message }}</span>
                                @enderror
                            </div>
                            <button type="submit" class="btn btn-primary">Create</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection