import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEnvironments } from '../api/hooks'
import { activateEnvironment, saveEnvironment, type ApiError } from '../api/client'
import { toast } from '../hooks/useToast'
import type { EnvironmentFormValues } from '../types'
import { usableEnvironments } from '../utils/usableEnvironments'
import { EnvironmentForm } from './EnvironmentForm'

export function EnvironmentSetup() {
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (values: EnvironmentFormValues) => saveEnvironment(values),
    onSuccess: (data) => {
      toast({ title: `Connected to '${data.active}'`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
    onError: (err: ApiError) => {
      // FE-11: a 502 with saved:true means the environment WAS stored --
      // refresh so it shows up under "Available environments".
      if (err.body?.saved) queryClient.invalidateQueries({ queryKey: ['environments'] })
      toast({ title: err.body?.saved ? 'Saved, but could not connect' : 'Could not connect', description: err.message, variant: 'error' })
    },
  })

  // A new identity (e.g. signing in through a second Okta org's gate) has no active environment yet, but
  // may already have environments shared with it: offer those here instead of only "add a new one".
  const { data: environments } = useEnvironments()
  const usable = usableEnvironments(environments?.environments)
  const activateMutation = useMutation({
    mutationFn: (env: { name: string; id: string }) => activateEnvironment(env.name, env.id),
    onSuccess: (data) => {
      toast({ title: `Connected to '${data.active}'`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
    onError: (err: Error) => toast({ title: 'Could not connect', description: err.message, variant: 'error' }),
  })

  const apiError = (mutation.error as ApiError | null)?.body?.saved ? undefined : (mutation.error as ApiError | null)?.body?.error

  return (
    <div className="max-w-md mx-auto px-6 py-16 flex flex-col gap-5">
      <header>
        <h1 className="text-lg font-semibold text-text">Connect to Okta Privileged Access</h1>
        <p className="text-xs text-text-faint mt-1">
          {usable.length > 0
            ? 'Use an environment that is already available to you, or add a new one.'
            : 'No environment is configured yet. Enter your OPA service-user credentials to get started — you can add more environments (e.g. dev / uat / prod) later from the gear menu.'}
        </p>
      </header>
      {usable.length > 0 && (
        <div className="card p-4 flex flex-col gap-2">
          <h2 className="text-sm font-semibold text-text">Available environments</h2>
          {usable.map(env => (
            <div key={env.id} className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm text-text truncate">{env.name}</div>
                <div className="text-xs text-text-faint truncate">
                  {env.is_own ? 'Yours' : 'Shared with you'}
                  {env.team_name ? ` · ${env.team_name}` : ''}
                </div>
              </div>
              <button
                type="button"
                className="btn-primary !py-1 !px-2 text-xs shrink-0"
                disabled={activateMutation.isPending}
                onClick={() => activateMutation.mutate(env)}
              >
                Use this environment
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="card p-4">
        {usable.length > 0 && <h2 className="text-sm font-semibold text-text mb-3">Add a new environment</h2>}
        <EnvironmentForm
          submitLabel="Save & Connect"
          isSubmitting={mutation.isPending}
          errorMessage={apiError}
          onSubmit={values => mutation.mutate(values)}
        />
      </div>
    </div>
  )
}
